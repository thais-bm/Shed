# client/backend/src/backend/serpent_enc.py
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .audit import SecurityAuditor

class SerpentProtocol:
    """
    Gerencia a criptografia simétrica com Serpent (modo CBC) e autenticação HMAC-SHA256.
    Implementa a arquitetura 'Encrypt-then-MAC': a mensagem é cifrada primeiro e o pacote
    resultante é assinado, garantindo que adulterações na rede sejam bloqueadas pelo 
    destinatário antes de qualquer tentativa de decifragem.
    """
    
    def __init__(self, session_key: bytes):
        """
        Recebe a chave de sessão mestre do ECDH e usa o HKDF para derivar duas chaves 
        distintas usando SHA-256: uma exclusiva para cifrar os dados (enc_key) e outra 
        exclusiva para assinar (mac_key), evitando vulnerabilidades de reuso de chave.
        """
        SecurityAuditor.log_step("SERPENT", "A derivar chaves filhas (Encrypt-then-MAC)...")
        kdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'shed-enc-mac')
        key_material = kdf.derive(session_key)
        
        self.enc_key = key_material[:32]
        self.mac_key = key_material[32:]

    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Cifra o texto em modo CBC (que gera um IV aleatório de 16 bytes automaticamente) 
        e calcula o lacre de integridade HMAC de 32 bytes sobre o resultado. 
        O pacote final gerado para a rede é a junção: [IV] + [Texto Cifrado] + [MAC].
        """
        iv_and_ciphertext = serpent_cbc_encrypt(self.enc_key, plaintext)
        
        # LOG DIDÁTICO
        iv_gerado = iv_and_ciphertext[:16]
        cifra_gerada = iv_and_ciphertext[16:]
        SecurityAuditor.log_step("SERPENT", "[EXPLICABILIDADE] Pacote Cifrado:", f"IV: {iv_gerado.hex()[:20]}... | Cifra: {cifra_gerada.hex()[:20]}...")
        
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv_and_ciphertext)
        mac = h.finalize()
        
        SecurityAuditor.log_step("SERPENT", "[EXPLICABILIDADE] Lacre HMAC:", f"MAC: {mac.hex()[:20]}...")
        SecurityAuditor.log_step("SERPENT", "Mensagem cifrada nativamente (CBC).", f"Tamanho final: {len(iv_and_ciphertext)} bytes + MAC(32)")
        
        return iv_and_ciphertext + mac

    def decrypt_message(self, payload: bytes) -> str:
        """
        Recebe o pacote da rede e fatia o lacre MAC (últimos 32 bytes). O sistema recalcula 
        a assinatura e valida a integridade ANTES de tocar na cifra. Se a assinatura bater, 
        o motor Serpent extrai o IV, desfaz a baralhação do modo CBC e devolve o texto limpo.
        """
        if len(payload) < 48:
            raise ValueError("Pacote corrompido ou muito pequeno.")
            
        mac_recebido = payload[-32:]
        iv_and_ciphertext = payload[:-32]
        
        # LOG DIDÁTICO
        iv_recebido = iv_and_ciphertext[:16]
        SecurityAuditor.log_step("SERPENT", "[EXPLICABILIDADE] Pacote Fatiado pelo Recebedor:", f"IV: {iv_recebido.hex()[:20]}... | MAC: {mac_recebido.hex()[:20]}...")
        
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv_and_ciphertext)
        try:
            h.verify(mac_recebido)
            SecurityAuditor.log_step("SERPENT", "Integridade da mensagem validada (HMAC correto).")
        except Exception:
            SecurityAuditor.log_step("SERPENT", "FALHA DE INTEGRIDADE!", "Pacote adulterado na rede.")
            raise ValueError("Falha na validação do HMAC.")

        plaintext_bytes = serpent_cbc_decrypt(self.enc_key, iv_and_ciphertext)
        
        msg = plaintext_bytes.decode('utf-8')
        SecurityAuditor.log_step("SERPENT", "Mensagem decifrada com sucesso.", f"Conteúdo extraído: '{msg}'")
        return msg