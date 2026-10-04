# src/backend/crypto.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .audit import SecurityAuditor

class ECDHManager:
    def __init__(self):
        # A curva SECP384R1 oferece um nível de segurança excelente e recomendável
        self.curve = ec.SECP384R1()

    def generate_key_pair(self):
        """Gera a chave privada e deriva a chave pública correspondente."""
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        
        SecurityAuditor.log_step("ECDH", "Par de chaves gerado.", f"Curva: {self.curve.name}")
        return private_key, public_key

    def export_public_key(self, public_key) -> bytes:
        """Exporta a chave pública para formato PEM (seguro para trafegar na rede)."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Mostra apenas um trecho no log para não poluir o terminal
        preview = pem.splitlines()[1].decode()[:20] 
        SecurityAuditor.log_step("ECDH", "Chave pública exportada para PEM.", f"Preview: {preview}...")
        return pem

    def load_public_key(self, pem_bytes: bytes):
        """Carrega a chave pública recebida do servidor."""
        public_key = serialization.load_pem_public_key(pem_bytes)
        SecurityAuditor.log_step("ECDH", "Chave pública do destinatário importada com sucesso.")
        return public_key

    def derive_sym_key(self, my_private_key, peer_public_key) -> bytes:
        """
        Cruza a chave privada local com a pública do destinatário.
        Usa HKDF para gerar uma chave simétrica de 256 bits para o Serpent.
        """
        # 1. O cruzamento matemático (Exchange)
        shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
        SecurityAuditor.log_step("ECDH", "Segredo compartilhado bruto derivado.", f"Tamanho: {len(shared_secret)} bytes")

        # 2. Key Derivation Function (KDF)
        # O Serpent suporta chaves de até 256 bits (32 bytes).
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits
            salt=None,
            info=b'shed-session-key', # Contexto para evitar reuso acidental de chaves
        ).derive(shared_secret)

        SecurityAuditor.log_step("SERPENT", "Chave simétrica de 256-bits gerada via HKDF.", f"Pronta para a cifra.")
        return derived_key