# client/backend/src/backend/session.py
import hashlib
import json
import time
from .crypto import ECDHManager, IdentityKeyManager
from .audit import SecurityAuditor
from .serpent_enc import SerpentProtocol

# Tolerância máxima para timestamps no futuro (relógios dessincronizados).
# Não há limite para mensagens "antigas": o Relé guarda mensagens offline (Store-and-Forward).
MAX_FUTURE_SKEW_SECONDS = 300


class ReplayError(ValueError):
    """Mensagem rejeitada pela proteção anti-replay (repetida, fora de ordem, refletida ou com timestamp inválido)."""


class SecureSession:
    """
    Representa uma sessão segura entre dois participantes.
    Suporta handshakes ECDH autenticados por assinatura ECDSA (Chave de Identidade).

    Proteção contra Replay: cada mensagem cifrada carrega, DENTRO do payload autenticado
    (Encrypt-then-MAC), um contador de sequência crescente por direção, um timestamp e o
    identificador do remetente. O receptor só aceita sequências estritamente maiores que a
    última recebida e rejeita mensagens refletidas de volta ao próprio remetente.
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
        self.send_seq = 0  # Último número de sequência enviado
        self.recv_seq = 0  # Último número de sequência aceito do par

    @classmethod
    def from_persisted_state(
        cls,
        session_key: bytes,
        my_pub_pem: bytes,
        peer_pub_pem: bytes,
        send_seq: int = 0,
        recv_seq: int = 0,
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
        instance.send_seq = send_seq
        instance.recv_seq = recv_seq
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
        self.send_seq = 0
        self.recv_seq = 0

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

    @staticmethod
    def _sender_id(public_key_pem: bytes) -> str:
        """Identificador curto de quem enviou (derivado da chave efêmera), para barrar mensagens refletidas."""
        return hashlib.sha256(public_key_pem).hexdigest()[:16]

    def encrypt(self, message: str) -> bytes:
        if not self.is_established:
            raise RuntimeError("A sessão segura ainda não foi estabelecida.")
        self.send_seq += 1
        SecurityAuditor.log_step(
            "REPLAY",
            f"Anti-replay (envio): cabeçalho seq={self.send_seq} embutido DENTRO do texto a cifrar.",
            "Campos: seq (contador), ts (timestamp), sid (identidade do remetente) + texto.",
        )
        envelope = {
            "seq": self.send_seq,
            "ts": int(time.time()),
            "sid": self._sender_id(self.get_public_key()),
            "text": message,
        }
        return self.serpent.encrypt_message(json.dumps(envelope, separators=(",", ":")))

    def decrypt(self, payload: bytes) -> str:
        if not self.is_established:
            raise RuntimeError("A sessão segura ainda não foi estabelecida.")
        # O HMAC é validado antes de qualquer interpretação: seq/ts/sid são autênticos.
        plaintext = self.serpent.decrypt_message(payload)
        try:
            envelope = json.loads(plaintext)
            seq, ts, sid, text = envelope["seq"], envelope["ts"], envelope["sid"], envelope["text"]
            if not isinstance(seq, int) or not isinstance(ts, int) or not isinstance(text, str):
                raise TypeError
        except (ValueError, KeyError, TypeError) as exc:
            self._reject("Payload sem cabeçalho anti-replay válido (seq/ts/sid).")
            raise ReplayError("Payload sem cabeçalho anti-replay válido (seq/ts/sid).") from exc

        if self.peer_public_key_pem is not None and sid != self._sender_id(self.peer_public_key_pem):
            self._reject("Mensagem não foi enviada pelo par desta sessão (possível reflexão).")
            raise ReplayError("Mensagem não foi enviada pelo par desta sessão (possível reflexão).")
        if seq <= self.recv_seq:
            self._reject(f"REPLAY DETECTADO: seq={seq} <= último aceito ({self.recv_seq}).")
            raise ReplayError(f"Replay detectado: seq={seq} <= último aceito ({self.recv_seq}).")
        if ts > time.time() + MAX_FUTURE_SKEW_SECONDS:
            self._reject("Timestamp da mensagem está no futuro além da tolerância.")
            raise ReplayError("Timestamp da mensagem está no futuro além da tolerância.")

        SecurityAuditor.log_step(
            "REPLAY",
            f"Anti-replay (recebimento): seq={seq} ACEITO (último aceito era {self.recv_seq}).",
            f"Remetente confere (sid {sid}) | timestamp={ts}",
        )
        self.recv_seq = seq
        return text

    @staticmethod
    def _reject(motivo: str) -> None:
        SecurityAuditor.log_step("REPLAY", f"MENSAGEM REJEITADA: {motivo}", "O pacote foi descartado e nada foi salvo no histórico.")
