# client/backend/src/backend/serpent_enc.py
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt
from cryptography.exceptions import InvalidSignature
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
    
    def __init__(self, session_key: bytes, audit: bool = True):
        """
        Recebe a chave de sessão mestre do ECDH e usa o HKDF para derivar duas chaves 
        distintas usando SHA-256: uma exclusiva para cifrar os dados (enc_key) e outra 
        exclusiva para assinar (mac_key), evitando vulnerabilidades de reuso de chave.

        `audit=False` silencia os logs didáticos (usado no cofre local, para que o conteúdo
        protegido, como a chave de sessão salva no SQLite, nunca apareça nos logs).
        """
        self._audit = audit
        kdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'shed-enc-mac')
        key_material = kdf.derive(session_key)
        
        self.enc_key = key_material[:32]
        self.mac_key = key_material[32:]

        if self._audit:
            SecurityAuditor.log_step(
                "SERPENT",
                "Chaves filhas derivadas da chave de sessão via HKDF-SHA256 (Encrypt-then-MAC).",
                f"enc_key (Serpent, 256 bits) : fingerprint {SecurityAuditor.fingerprint(self.enc_key)}\n"
                f"mac_key (HMAC-SHA256, 256 bits): fingerprint {SecurityAuditor.fingerprint(self.mac_key)}\n"
                "Chaves separadas: a chave que cifra nunca é a mesma que autentica.",
            )

    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Cifra o texto em modo CBC (que gera um IV aleatório de 16 bytes automaticamente) 
        e calcula o lacre de integridade HMAC de 32 bytes sobre o resultado. 
        O pacote final gerado para a rede é a junção: [IV] + [Texto Cifrado] + [MAC].
        """
        iv_and_ciphertext = serpent_cbc_encrypt(self.enc_key, plaintext)
        
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv_and_ciphertext)
        mac = h.finalize()

        if self._audit:
            iv_gerado = iv_and_ciphertext[:16]
            cifra_gerada = iv_and_ciphertext[16:]
            total = len(iv_and_ciphertext) + len(mac)
            SecurityAuditor.log_step(
                "SERPENT",
                "CIFRANDO mensagem: Serpent-CBC + HMAC-SHA256 (Encrypt-then-MAC).",
                f"Entrada (texto + cabeçalho anti-replay): {len(plaintext.encode('utf-8'))} bytes\n"
                f"IV aleatório (16 B)   : {iv_gerado.hex()}\n"
                f"Cifra Serpent-CBC     : {cifra_gerada.hex()[:40]}... ({len(cifra_gerada)} bytes)\n"
                f"HMAC-SHA256 (32 B)    : {mac.hex()[:40]}... (calculado sobre IV + cifra)\n"
                f"Pacote para a rede    : 16 + {len(cifra_gerada)} + 32 = {total} bytes",
            )
        
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
        
        if self._audit:
            SecurityAuditor.log_step(
                "SERPENT",
                "DECIFRANDO: pacote recebido da rede.",
                f"Pacote                : {len(payload)} bytes = IV 16 + cifra {len(iv_and_ciphertext) - 16} + HMAC 32\n"
                f"IV                    : {iv_and_ciphertext[:16].hex()}\n"
                f"HMAC recebido         : {mac_recebido.hex()[:40]}...",
            )
        
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv_and_ciphertext)
        try:
            h.verify(mac_recebido)
            if self._audit:
                SecurityAuditor.log_step(
                    "SERPENT",
                    "HMAC VÁLIDO: integridade e autenticidade confirmadas ANTES de decifrar.",
                )
        except InvalidSignature as exc:
            if self._audit:
                SecurityAuditor.log_step(
                    "SERPENT",
                    "FALHA DE INTEGRIDADE! HMAC inválido: pacote adulterado ou chave errada.",
                    "A cifra NÃO foi decifrada: o pacote foi descartado antes de tocar no Serpent.",
                )
            raise ValueError("Falha na validação do HMAC.") from exc

        plaintext_bytes = serpent_cbc_decrypt(self.enc_key, iv_and_ciphertext)
        
        msg = plaintext_bytes.decode('utf-8')
        if self._audit:
            SecurityAuditor.log_step(
                "SERPENT",
                "Mensagem decifrada com sucesso.",
                f"Conteúdo extraído (cabeçalho anti-replay + texto): {msg}",
            )
        return msg
