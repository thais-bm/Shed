# client/backend/src/backend/session.py
import hashlib
from .crypto import ECDHManager, IdentityKeyManager
from .serpent_enc import SerpentProtocol


class SecureSession:
    """
    Representa uma sessão segura entre dois participantes.
    Suporta handshakes ECDH autenticados por assinatura ECDSA (Chave de Identidade).
    """

    def __init__(self):
        self.ecdh = ECDHManager()
        self.identity_manager = IdentityKeyManager()
        self.private_key, self.public_key = self.ecdh.generate_key_pair()
        # A chave efêmera não muda durante a sessão: exporta para PEM uma única vez
        self._public_key_pem = self.ecdh.export_public_key(self.public_key)
        self.session_key: bytes | None = None
        self.serpent: SerpentProtocol | None = None
        self.peer_public_key_pem: bytes | None = None  # Retém a chave para a impressão digital

    @classmethod
    def from_persisted_state(
        cls,
        session_key: bytes,
        my_pub_pem: bytes,
        peer_pub_pem: bytes,
    ) -> "SecureSession":
        """Restaura uma sessão já estabelecida a partir do cofre SQLite local sem refazer ECDH."""
        instance = cls.__new__(cls)
        instance.ecdh = None
        instance.identity_manager = IdentityKeyManager()
        instance.private_key = None
        instance.public_key = None
        instance._public_key_pem = my_pub_pem
        instance.peer_public_key_pem = peer_pub_pem
        instance.session_key = session_key
        instance.serpent = SerpentProtocol(session_key)
        return instance

    @property
    def is_established(self) -> bool:
        """Propriedade auxiliar para verificar se a sessão já está pronta para cifrar."""
        return self.serpent is not None

    def get_public_key(self) -> bytes:
        return self._public_key_pem

    def get_signed_public_key(self, identity_private_key) -> tuple[bytes, bytes]:
        """
        Exporta a chave pública efêmera ECDH e gera sua assinatura digital ECDSA
        usando a Chave Privada de Identidade permanente do usuário.
        """
        pub_pem = self.get_public_key()
        signature = self.identity_manager.sign_ephemeral_key(identity_private_key, pub_pem)
        return pub_pem, signature

    def establish_session(
        self,
        peer_public_key_pem: bytes,
        signature: bytes | None = None,
        peer_identity_public_key_pem: bytes | None = None,
    ):
        # 1. Se a chave de identidade do par foi informada, exige e valida a assinatura ECDSA
        if peer_identity_public_key_pem is not None:
            if signature is None:
                raise ValueError("Assinatura ECDSA ausente no handshake autenticado.")
            self.identity_manager.verify_ephemeral_key(
                peer_identity_public_key_pem=peer_identity_public_key_pem,
                ephemeral_public_key_pem=peer_public_key_pem,
                signature=signature,
            )

        # 2. Guarda a chave pública recebida do par e deriva a chave simétrica
        self.peer_public_key_pem = peer_public_key_pem
        peer_public_key = self.ecdh.load_public_key(peer_public_key_pem)
        self.session_key = self.ecdh.derive_sym_key(self.private_key, peer_public_key)
        self.serpent = SerpentProtocol(self.session_key)

    def get_safety_number(self) -> str:
        if not self.is_established or self.peer_public_key_pem is None:
            raise RuntimeError("A sessão precisa estar estabelecida para gerar o Safety Number.")

        my_pub = self.get_public_key()
        chaves_ordenadas = sorted([my_pub, self.peer_public_key_pem])
        digest = hashlib.sha256(chaves_ordenadas[0] + chaves_ordenadas[1]).digest()

        blocos = []
        for i in range(0, 12, 2):
            numero = int.from_bytes(digest[i : i + 2], byteorder="big") % 100000
            blocos.append(f"{numero:05d}")

        return " ".join(blocos)

    def encrypt(self, message: str) -> bytes:
        if not self.is_established:
            raise RuntimeError("A sessão segura ainda não foi estabelecida.")
        return self.serpent.encrypt_message(message)

    def decrypt(self, payload: bytes) -> str:
        if not self.is_established:
            raise RuntimeError("A sessão segura ainda não foi estabelecida.")
        return self.serpent.decrypt_message(payload)