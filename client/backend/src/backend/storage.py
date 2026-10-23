# client/backend/src/backend/storage.py
import sqlite3
from pathlib import Path
from .audit import SecurityAuditor


class LocalStorage:
    # Caminhos de banco cujo schema já foi criado neste processo (evita CREATE TABLE a cada mensagem)
    _initialized_paths: set[str] = set()

    def __init__(self, owner_username: str, db_dir: str | Path = "data"):
        """
        Cada usuário rodando o cliente local terá seu próprio banco de dados.
        Ex: data/alice_history.db
        """
        self.owner = owner_username.strip().lower()

        # Cria a pasta 'data' na raiz do backend, se não existir
        db_dir_path = Path(db_dir)
        db_dir_path.mkdir(parents=True, exist_ok=True)

        self.db_path = db_dir_path / f"{self.owner}_history.db"

        path_key = str(self.db_path.resolve())
        if path_key not in LocalStorage._initialized_paths or not self.db_path.exists():
            self._init_db()
            LocalStorage._initialized_paths.add(path_key)

    def _init_db(self):
        """Cria as tabelas caso seja a primeira vez abrindo o aplicativo."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact_username TEXT NOT NULL,
                    is_sender BOOLEAN NOT NULL,
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Guarda a Chave de Identidade local (a chave privada fica cifrada com local_storage_key)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS local_identity (
                    username TEXT PRIMARY KEY,
                    encrypted_private_key_pem BLOB NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # TOFU (Trust On First Use): fixa a chave de identidade pública de cada contato
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trusted_identities (
                    contact_username TEXT PRIMARY KEY,
                    public_identity_key_pem TEXT NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS established_sessions (
                    contact_username TEXT PRIMARY KEY,
                    encrypted_session_key BLOB NOT NULL,
                    my_ephemeral_pub_pem TEXT NOT NULL,
                    peer_ephemeral_pub_pem TEXT NOT NULL,
                    established_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    send_seq INTEGER NOT NULL DEFAULT 0,
                    recv_seq INTEGER NOT NULL DEFAULT 0
                )
            ''')
            # Migração: bancos criados antes da proteção anti-replay não têm os contadores
            existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(established_sessions)")}
            for col in ("send_seq", "recv_seq"):
                if col not in existing_cols:
                    cursor.execute(f"ALTER TABLE established_sessions ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        SecurityAuditor.log_step("STORAGE", "Banco de dados local inicializado.", f"Arquivo: {self.db_path}")

    # -------------------------------------------------------------------------
    # Identidade Local (Cifrada com a metade local do Split-Key)
    # -------------------------------------------------------------------------
    def save_my_identity(self, encrypted_private_key_pem: bytes, public_key_pem: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT OR REPLACE INTO local_identity (username, encrypted_private_key_pem, public_key_pem)
                VALUES (?, ?, ?)
                ''',
                (self.owner, encrypted_private_key_pem, public_key_pem),
            )
            conn.commit()
        SecurityAuditor.log_step(
            "STORAGE",
            "Chave de Identidade local salva no cofre SQLite.",
            "Chave privada protegida por local_storage_key.",
        )

    def get_my_identity(self) -> dict | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT encrypted_private_key_pem, public_key_pem
                FROM local_identity
                WHERE username = ?
                ''',
                (self.owner,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    # -------------------------------------------------------------------------
    # TOFU (Trust On First Use) para Chaves de Identidade dos Contatos
    # -------------------------------------------------------------------------
    def verify_or_pin_contact_identity(self, contact_username: str, public_identity_key_pem: str) -> bool:
        """
        Verifica se a chave de identidade do contato bate com a chave fixada no primeiro contato (TOFU).
        Se for o primeiro contato, fixa (salva) a chave. Se divergir, bloqueia por suspeita de MitM!
        """
        contact = contact_username.strip().lower()
        normalized_pem = public_identity_key_pem.strip()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT public_identity_key_pem FROM trusted_identities WHERE contact_username = ?",
                (contact,),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.execute(
                    "INSERT INTO trusted_identities (contact_username, public_identity_key_pem) VALUES (?, ?)",
                    (contact, normalized_pem),
                )
                conn.commit()
                SecurityAuditor.log_step(
                    "TOFU",
                    f"Primeiro contato com '{contact}': Chave de Identidade FIXADA no banco local.",
                    f"Fingerprint fixado: {SecurityAuditor.fingerprint(normalized_pem + chr(10))} (qualquer mudança futura será bloqueada)",
                )
                return True

            if row["public_identity_key_pem"].strip() != normalized_pem:
                SecurityAuditor.log_step(
                    "TOFU",
                    f"ALERTA MITM: Chave de Identidade de '{contact}' divergiu da chave salva!",
                )
                raise ValueError(
                    f"ALERTA MITM (TOFU): A Chave de Identidade de '{contact}' mudou! Conexão bloqueada."
                )

            SecurityAuditor.log_step(
                "TOFU",
                f"Chave de Identidade de '{contact}' confere com a fixada no primeiro contato.",
                f"Fingerprint: {SecurityAuditor.fingerprint(normalized_pem + chr(10))}",
            )
            return True

    def get_pinned_contact_identity(self, contact_username: str) -> str | None:
        contact = contact_username.strip().lower()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT public_identity_key_pem FROM trusted_identities WHERE contact_username = ?",
                (contact,),
            )
            row = cursor.fetchone()
            return row[0] if row else None

    # -------------------------------------------------------------------------
    # Histórico de Mensagens
    # -------------------------------------------------------------------------
    def save_message(self, contact_username: str, is_sender: bool, content: str):
        """
        Salva a mensagem limpa no histórico.
        is_sender = True (Mensagem que eu enviei)
        is_sender = False (Mensagem que eu recebi)
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO messages (contact_username, is_sender, content) VALUES (?, ?, ?)',
                (contact_username.strip().lower(), is_sender, content)
            )
            conn.commit()

        direcao = "Enviada para" if is_sender else "Recebida de"
        SecurityAuditor.log_step("STORAGE", f"Mensagem registrada no histórico.", f"{direcao} {contact_username}")

    def get_chat_history(self, contact_username: str) -> list[dict]:
        """
        Retorna toda a conversa com um contato específico, formatada
        como uma lista de dicionários para a API devolver ao React.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT is_sender, content, timestamp 
                FROM messages 
                WHERE contact_username = ? 
                ORDER BY timestamp ASC
                ''',
                (contact_username.strip().lower(),)
            )
            rows = cursor.fetchall()

        return [dict(row) for row in rows]


# -------------------------------------------------------------------------
    # Cofre de Sessões E2EE Estabelecidas (Garante Handshake Único Permanente)
    # -------------------------------------------------------------------------
    def save_established_session(
        self,
        contact_username: str,
        session_key: bytes,
        my_ephemeral_pub_pem: bytes,
        peer_ephemeral_pub_pem: bytes,
        local_storage_key: bytes,
        send_seq: int = 0,
        recv_seq: int = 0,
    ) -> None:
        from .serpent_enc import SerpentProtocol

        contact = contact_username.strip().lower()
        vault = SerpentProtocol(local_storage_key, audit=False)  # cofre: o conteúdo nunca vai para os logs
        encrypted_key = vault.encrypt_message(session_key.hex())

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT OR REPLACE INTO established_sessions
                (contact_username, encrypted_session_key, my_ephemeral_pub_pem, peer_ephemeral_pub_pem,
                 send_seq, recv_seq)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (
                    contact,
                    encrypted_key,
                    my_ephemeral_pub_pem.decode("utf-8"),
                    peer_ephemeral_pub_pem.decode("utf-8"),
                    send_seq,
                    recv_seq,
                ),
            )
            conn.commit()
        SecurityAuditor.log_step(
            "STORAGE",
            f"Sessão E2EE definitiva com '{contact}' cifrada e salva no SQLite local.",
        )

    def load_all_established_sessions(self, local_storage_key: bytes) -> dict:
        from .serpent_enc import SerpentProtocol
        from .session import SecureSession

        vault = SerpentProtocol(local_storage_key, audit=False)  # cofre: o conteúdo nunca vai para os logs
        sessions = {}

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT contact_username, encrypted_session_key, my_ephemeral_pub_pem, peer_ephemeral_pub_pem,
                       send_seq, recv_seq
                FROM established_sessions
                """
            )
            rows = cursor.fetchall()

        for row in rows:
            contact = row["contact_username"]
            try:
                session_key_hex = vault.decrypt_message(row["encrypted_session_key"])
                sessions[contact] = SecureSession.from_persisted_state(
                    session_key=bytes.fromhex(session_key_hex),
                    my_pub_pem=row["my_ephemeral_pub_pem"].encode("utf-8"),
                    peer_pub_pem=row["peer_ephemeral_pub_pem"].encode("utf-8"),
                    send_seq=row["send_seq"],
                    recv_seq=row["recv_seq"],
                )
            except Exception as exc:
                SecurityAuditor.log_step("STORAGE", f"Falha ao restaurar sessão com '{contact}': {exc}")

        if sessions:
            SecurityAuditor.log_step(
                "STORAGE",
                f"{len(sessions)} sessão(ões) E2EE restaurada(s) do cofre local (sem necessidade de novo handshake).",
            )
        return sessions

    def update_session_counters(self, contact_username: str, send_seq: int, recv_seq: int) -> None:
        """Persiste os contadores anti-replay para que sobrevivam a reinícios do backend."""
        contact = contact_username.strip().lower()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE established_sessions SET send_seq = ?, recv_seq = ? WHERE contact_username = ?",
                (send_seq, recv_seq, contact),
            )
            conn.commit()

    def delete_established_session(self, contact_username: str) -> None:
        contact = contact_username.strip().lower()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM established_sessions WHERE contact_username = ?", (contact,))
            conn.commit()