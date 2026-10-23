# src/backend/crypto.py
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .audit import SecurityAuditor


class PasswordKeyDeriver:
    """
    Implementa a Derivação de Chave Dividida (Split-Key Derivation) no cliente.
    A senha mestre do usuário NUNCA é enviada ao servidor relé:
      - Metade 1 (local_storage_key - 32 bytes): fica 100% na máquina local para cifrar chaves/dados.
      - Metade 2 (relay_login_secret - 64 hex chars): enviada ao relé para autenticação Argon2.
    """

    @staticmethod
    def derive_master_keys(username: str, master_password: str) -> tuple[bytes, str]:
        normalized_user = username.strip().lower().encode("utf-8")
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=normalized_user,
            info=b"shed-master-password-split",
        )
        key_material = kdf.derive(master_password.encode("utf-8"))

        local_storage_key = key_material[:32]
        relay_login_secret = key_material[32:].hex()

        SecurityAuditor.banner(
            "CHAVES 1/4 - SPLIT-KEY DA SENHA (HKDF-SHA256)",
            "Uma senha -> duas chaves independentes. O Relé só recebe uma delas.",
        )
        SecurityAuditor.log_step(
            "AUTH",
            f"Split-Key concluído para '{username.strip().lower()}'.",
            "Entrada            : senha mestre (fica só na memória; nunca é enviada)\n"
            f"local_storage_key  : 32 B | fingerprint {SecurityAuditor.fingerprint(local_storage_key)} | NUNCA sai do dispositivo (cifra o cofre SQLite)\n"
            f"relay_login_secret : 32 B | fingerprint {SecurityAuditor.fingerprint(relay_login_secret)} | único valor enviado ao Relé (guardado lá como hash Argon2)\n"
            "Garantia           : o Relé não consegue derivar a local_storage_key a partir do que recebe.",
        )
        return local_storage_key, relay_login_secret


class IdentityKeyManager:
    """
    Gerencia o par de Chaves de Identidade de longo prazo (ECDSA na curva SECP384R1).
    Usado para assinar digitalmente as chaves efêmeras do handshake ECDH, impedindo
    que o Servidor Relé ou um atacante substitua chaves públicas na rede (MitM).
    """

    def __init__(self):
        self.curve = ec.SECP384R1()

    def generate_identity_key_pair(self):
        """Gera a chave privada e pública de identidade permanente da conta."""
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        SecurityAuditor.banner(
            "CHAVES 2/4 - IDENTIDADE PERMANENTE DA CONTA (ECDSA)",
            "Prova quem você é: assina as chaves efêmeras do handshake.",
        )
        SecurityAuditor.log_step(
            "ECDSA",
            "Par de Chaves de Identidade (ECDSA) gerado.",
            f"Curva              : {self.curve.name} (384 bits)\n"
            f"Chave pública      : fingerprint {SecurityAuditor.fingerprint(pub_pem)} (será publicada no Relé)\n"
            "Chave privada      : NUNCA sai do dispositivo; será salva no SQLite cifrada com a local_storage_key.",
        )
        return private_key, public_key

    def export_public_key(self, public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_key(
        self,
        private_key,
        local_storage_key: bytes | None = None,
    ) -> bytes:
        """
        Exporta a chave privada de identidade em PEM.
        Se local_storage_key for fornecida, cifra a chave privada antes de salvar no disco.
        """
        encryption = (
            serialization.BestAvailableEncryption(local_storage_key)
            if local_storage_key
            else serialization.NoEncryption()
        )
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def load_private_key(
        self,
        pem_bytes: bytes,
        local_storage_key: bytes | None = None,
    ):
        return serialization.load_pem_private_key(
            pem_bytes,
            password=local_storage_key,
        )

    def sign_ephemeral_key(
        self,
        identity_private_key,
        ephemeral_public_key_pem: bytes,
    ) -> bytes:
        """Assina a chave pública efêmera ECDH com a chave privada de identidade (ECDSA-SHA256)."""
        signature = identity_private_key.sign(
            ephemeral_public_key_pem,
            ec.ECDSA(hashes.SHA256()),
        )
        SecurityAuditor.log_step(
            "ECDSA",
            "Chave efêmera ECDH assinada com ECDSA-SHA256.",
            f"Assinatura         : {signature.hex()[:32]}... ({len(signature)} bytes, ECDSA-SHA256)\n"
            f"Chave efêmera      : fingerprint {SecurityAuditor.fingerprint(ephemeral_public_key_pem)} (coberta pela assinatura)\n"
            "Efeito             : o contato (e ninguém no meio do caminho) prova que esta chave veio de você.",
        )
        return signature

    def verify_ephemeral_key(
        self,
        peer_identity_public_key_pem: bytes,
        ephemeral_public_key_pem: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verifica se a chave pública efêmera ECDH foi realmente assinada pela
        Chave de Identidade do contato. Dispara ValueError se houver adulteração.
        """
        peer_identity_pub = serialization.load_pem_public_key(peer_identity_public_key_pem)
        try:
            peer_identity_pub.verify(
                signature,
                ephemeral_public_key_pem,
                ec.ECDSA(hashes.SHA256()),
            )
            SecurityAuditor.log_step(
                "ECDSA",
                "Assinatura ECDSA do contato validada com sucesso!",
                f"Identidade do contato: fingerprint {SecurityAuditor.fingerprint(peer_identity_public_key_pem)}\n"
                f"Chave efêmera recebida: fingerprint {SecurityAuditor.fingerprint(ephemeral_public_key_pem)}\n"
                "Efeito: a chave efêmera pertence mesmo a este contato (sem substituição por MitM).",
            )
            return True
        except InvalidSignature as exc:
            SecurityAuditor.log_step(
                "ECDSA",
                "ALERTA MITM: Assinatura ECDSA inválida no handshake!",
            )
            raise ValueError(
                "Assinatura ECDSA inválida! A chave pública efêmera não pertence à identidade do contato."
            ) from exc


class ECDHManager:
    def __init__(self):
        # A curva SECP384R1 oferece um nível de segurança excelente e recomendável
        self.curve = ec.SECP384R1()

    def generate_key_pair(self):
        """Gera a chave privada e deriva a chave pública correspondente."""
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        
        SecurityAuditor.log_step(
            "ECDH",
            "Par de chaves EFÊMERAS ECDH gerado (uma por sessão).",
            f"Curva: {self.curve.name} | A chave privada efêmera nunca é enviada nem exibida.",
        )
        return private_key, public_key

    def export_public_key(self, public_key) -> bytes:
        """Exporta a chave pública para formato PEM (seguro para trafegar na rede)."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        SecurityAuditor.log_step(
            "ECDH",
            "Chave pública efêmera exportada (PEM) para envio pela rede.",
            f"Fingerprint: {SecurityAuditor.fingerprint(pem)} (o mesmo valor aparece no terminal do Relé)",
        )
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
        SecurityAuditor.banner(
            "CHAVES 4/4 - SEGREDO COMPARTILHADO (ECDH + HKDF-SHA256)",
            "Cada lado combina a SUA privada com a PÚBLICA do outro: o segredo nunca trafega.",
        )
        SecurityAuditor.log_step(
            "ECDH",
            "Segredo compartilhado bruto derivado (ECDH).",
            f"Tamanho: {len(shared_secret)} bytes | O valor bruto não é exibido nem usado direto como chave.",
        )

        # 2. Key Derivation Function (KDF)
        # O Serpent suporta chaves de até 256 bits (32 bytes).
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits
            salt=None,
            info=b'shed-session-key', # Contexto para evitar reuso acidental de chaves
        ).derive(shared_secret)

        SecurityAuditor.log_step(
            "SERPENT",
            "Chave de sessão de 256 bits gerada via HKDF-SHA256.",
            "Contexto (info)  : 'shed-session-key'\n"
            f"Fingerprint      : {SecurityAuditor.fingerprint(derived_key)}\n"
            "Confira          : este fingerprint deve ser IGUAL nos terminais dos dois contatos.",
        )
        return derived_key