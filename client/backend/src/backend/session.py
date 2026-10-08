from .crypto import ECDHManager
from .serpent_enc import SerpentProtocol

class SecureSession:
    """
    Representa uma sessão segura entre dois participantes.

    Responsabilidades:
    - Gerar o par de chaves ECDH local.
    - Receber a chave pública do outro participante.
    - Derivar a chave simétrica compartilhada.
    - Criar o protocolo Serpent + HMAC.
    - Cifrar e decifrar mensagens.
    """

    def __init__(self):
        # Gerenciador responsável pelo ECDH
        self.ecdh = ECDHManager()

        # Gera as chaves da própria sessão
        self.private_key, self.public_key = (
            self.ecdh.generate_key_pair()
        )

        # O protocolo Serpent só será criado
        # depois que o handshake for concluído.
        self.serpent = None

    def get_public_key(self) -> bytes:
        """
        Retorna a chave pública em formato PEM.

        Essa chave pode ser enviada para o outro participante.
        """

        return self.ecdh.export_public_key(self.public_key)

    def establish_session(self, peer_public_key_pem: bytes):
        """
        Recebe a chave pública do outro participante e
        estabelece a chave simétrica compartilhada.
        """

        # Converte PEM para objeto de chave pública
        peer_public_key = self.ecdh.load_public_key(
            peer_public_key_pem
        )

        # ECDH + HKDF
        session_key = self.ecdh.derive_sym_key(
            self.private_key,
            peer_public_key
        )

        # Cria o protocolo Serpent + HMAC
        self.serpent = SerpentProtocol(session_key)

    def encrypt(self, message: str) -> bytes:
        """
        Cifra uma mensagem usando a sessão estabelecida.
        """

        if self.serpent is None:
            raise RuntimeError(
                "A sessão segura ainda não foi estabelecida."
            )

        return self.serpent.encrypt_message(message)

    def decrypt(self, payload: bytes) -> str:
        """
        Decifra uma mensagem recebida.
        """

        if self.serpent is None:
            raise RuntimeError(
                "A sessão segura ainda não foi estabelecida."
            )

        return self.serpent.decrypt_message(payload)