import hashlib
from .crypto import ECDHManager
from .serpent_enc import SerpentProtocol


class SecureSession:
    """
    Representa uma sessão segura entre dois participantes.
    """

    def __init__(self):
        self.ecdh = ECDHManager()
        self.private_key, self.public_key = self.ecdh.generate_key_pair()
        self.serpent = None
        self.peer_public_key_pem: bytes | None = None  # Retém a chave para a impressão digital

    @property
    def is_established(self) -> bool:
        """Propriedade auxiliar para verificar se a sessão já está pronta para cifrar."""
        return self.serpent is not None

    def get_public_key(self) -> bytes:
        return self.ecdh.export_public_key(self.public_key)

    def establish_session(self, peer_public_key_pem: bytes):
        # 1. Guarda a chave pública recebida do par
        self.peer_public_key_pem = peer_public_key_pem

        peer_public_key = self.ecdh.load_public_key(peer_public_key_pem)
        session_key = self.ecdh.derive_sym_key(self.private_key, peer_public_key)
        self.serpent = SerpentProtocol(session_key)

    def get_safety_number(self) -> str:
        """
        Gera uma impressão digital (Fingerprint) determinística da sessão.

        Ordena as duas chaves públicas em ordem lexicográfica e calcula um hash SHA-256.
        Garante que Alice e Bob obtenham o mesmo código exato, independentemente
        de quem iniciou o handshake. Se houver um MitM, os números divergem.
        """
        if not self.is_established or self.peer_public_key_pem is None:
            raise RuntimeError("A sessão precisa estar estabelecida para gerar o Safety Number.")

        my_pub = self.get_public_key()

        # Ordenação garante: Hash(A + B) == Hash(B + A)
        chaves_ordenadas = sorted([my_pub, self.peer_public_key_pem])
        digest = hashlib.sha256(chaves_ordenadas[0] + chaves_ordenadas[1]).digest()

        # Formata os primeiros 12 bytes do digest em 6 blocos numéricos de 5 dígitos
        blocos = []
        for i in range(0, 12, 2):
            numero = int.from_bytes(digest[i: i + 2], byteorder="big") % 100000
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