import os
import sqlite3
from pathlib import Path


class RelayDatabase:
    """
    Gerencia o banco de dados SQLite do Servidor Relé.
    Armazena apenas metadados de contas, chaves públicas de identidade,
    grafo de amizades e fila de envelopes cifrados offline.
    """

    _initialized_paths: set[Path] = set()

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            env_path = os.getenv("SHED_RELAY_DB")
            if env_path:
                self.db_path = Path(env_path)
            else:
                db_dir = Path("data")
                db_dir.mkdir(exist_ok=True)
                self.db_path = db_dir / "relay.db"
        else:
            self.db_path = Path(db_path)
            if self.db_path.parent != Path("."):
                self.db_path.parent.mkdir(parents=True, exist_ok=True)

        resolved_path = self.db_path.resolve()
        if resolved_path not in RelayDatabase._initialized_paths or not self.db_path.exists():
            self._init_db()
            RelayDatabase._initialized_paths.add(resolved_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()

            # Tabela de usuários
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_identity_key TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # Tabela de solicitações e vínculos de amizade
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS friendships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requester_username TEXT NOT NULL,
                    addressee_username TEXT NOT NULL,
                    status TEXT CHECK(status IN ('PENDING', 'ACCEPTED')) NOT NULL DEFAULT 'PENDING',
                    handshake_completed INTEGER NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(requester_username, addressee_username),
                    FOREIGN KEY(requester_username) REFERENCES users(username),
                    FOREIGN KEY(addressee_username) REFERENCES users(username)
                )
                """
            )

            # Migração segura: adiciona a coluna caso o banco relay.db já exista de execuções anteriores
            cursor.execute("PRAGMA table_info(friendships)")
            existing_columns = [row["name"] for row in cursor.fetchall()]
            if "handshake_completed" not in existing_columns:
                cursor.execute(
                    "ALTER TABLE friendships ADD COLUMN handshake_completed INTEGER NOT NULL DEFAULT 0"
                )

            # Fila de envelopes E2EE para destinatários desconectados (Store-and-Forward)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_username TEXT NOT NULL,
                    sender_username TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    # -------------------------------------------------------------------------
    # Usuários
    # -------------------------------------------------------------------------
    def create_user(
        self,
        username: str,
        password_hash: str,
        public_identity_key: str | None = None,
    ) -> dict:
        username = username.strip().lower()
        try:
            with self._connect() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, public_identity_key)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, public_identity_key),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Nome de usuário já está em uso.") from exc

        user = self.get_user(username)
        assert user is not None
        return user

    def get_user(self, username: str) -> dict | None:
        username = username.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, password_hash, public_identity_key, created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def search_users(self, query: str, exclude_username: str | None = None) -> list[dict]:
        pattern = f"%{query.strip().lower()}%"
        with self._connect() as conn:
            cursor = conn.cursor()
            if exclude_username:
                cursor.execute(
                    """
                    SELECT username, public_identity_key, created_at
                    FROM users
                    WHERE username LIKE ? AND username != ?
                    ORDER BY username ASC
                    LIMIT 25
                    """,
                    (pattern, exclude_username.strip().lower()),
                )
            else:
                cursor.execute(
                    """
                    SELECT username, public_identity_key, created_at
                    FROM users
                    WHERE username LIKE ?
                    ORDER BY username ASC
                    LIMIT 25
                    """,
                    (pattern,),
                )
            return [dict(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # Amizades (Solicitações, Aceite, Remoção e Listagem)
    # -------------------------------------------------------------------------
    def send_friend_request(self, requester: str, addressee: str) -> str:
        requester = requester.strip().lower()
        addressee = addressee.strip().lower()

        if requester == addressee:
            raise ValueError("Você não pode adicionar a si mesmo.")

        if not self.get_user(addressee):
            raise LookupError("Usuário destinatário não encontrado.")

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT requester_username, addressee_username, status
                FROM friendships
                WHERE (requester_username = ? AND addressee_username = ?)
                   OR (requester_username = ? AND addressee_username = ?)
                """,
                (requester, addressee, addressee, requester),
            )
            existing = cursor.fetchone()

            if existing:
                if existing["status"] == "ACCEPTED":
                    raise ValueError("Vocês já são amigos.")
                if existing["requester_username"] == requester:
                    raise ValueError("Solicitação de amizade já enviada.")
                # Se a outra pessoa já havia enviado um convite pendente, aceita automaticamente!
                cursor.execute(
                    """
                    UPDATE friendships
                    SET status = 'ACCEPTED', updated_at = CURRENT_TIMESTAMP
                    WHERE requester_username = ? AND addressee_username = ?
                    """,
                    (addressee, requester),
                )
                conn.commit()
                return "ACCEPTED"

            cursor.execute(
                """
                INSERT INTO friendships (requester_username, addressee_username, status)
                VALUES (?, ?, 'PENDING')
                """,
                (requester, addressee),
            )
            conn.commit()
            return "PENDING"

    def respond_friend_request(self, addressee: str, requester: str, accept: bool) -> str:
        addressee = addressee.strip().lower()
        requester = requester.strip().lower()

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, status
                FROM friendships
                WHERE requester_username = ? AND addressee_username = ?
                """,
                (requester, addressee),
            )
            row = cursor.fetchone()
            if not row:
                raise LookupError("Solicitação de amizade não encontrada.")
            if row["status"] == "ACCEPTED":
                raise ValueError("Esta solicitação já foi aceita.")

            if accept:
                cursor.execute(
                    """
                    UPDATE friendships
                    SET status = 'ACCEPTED', updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (row["id"],),
                )
                conn.commit()
                return "ACCEPTED"
            else:
                cursor.execute("DELETE FROM friendships WHERE id = ?", (row["id"],))
                conn.commit()
                return "REJECTED"

    def remove_friend(self, user_a: str, user_b: str) -> bool:
        user_a = user_a.strip().lower()
        user_b = user_b.strip().lower()

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                DELETE FROM friendships
                WHERE (requester_username = ? AND addressee_username = ?)
                   OR (requester_username = ? AND addressee_username = ?)
                """,
                (user_a, user_b, user_b, user_a),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_friends_list(self, username: str) -> dict[str, list[str]]:
        username = username.strip().lower()
        friends: list[str] = []
        pending_received: list[str] = []
        pending_sent: list[str] = []

        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT requester_username, addressee_username, status
                FROM friendships
                WHERE requester_username = ? OR addressee_username = ?
                ORDER BY updated_at DESC
                """,
                (username, username),
            )
            for row in cursor.fetchall():
                req = row["requester_username"]
                addr = row["addressee_username"]
                st = row["status"]

                if st == "ACCEPTED":
                    other = addr if req == username else req
                    friends.append(other)
                elif st == "PENDING":
                    if addr == username:
                        pending_received.append(req)
                    else:
                        pending_sent.append(addr)

        return {
            "friends": friends,
            "pending_received": pending_received,
            "pending_sent": pending_sent,
        }

    def are_friends(self, user_a: str, user_b: str) -> bool:
        """Verifica se dois usuários possuem vínculo de amizade ACCEPTED."""
        user_a = user_a.strip().lower()
        user_b = user_b.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 1
                FROM friendships
                WHERE ((requester_username = ? AND addressee_username = ?)
                    OR (requester_username = ? AND addressee_username = ?))
                  AND status = 'ACCEPTED'
                LIMIT 1
                """,
                (user_a, user_b, user_b, user_a),
            )
            return cursor.fetchone() is not None

    # -------------------------------------------------------------------------
    # Utilitarios para Handshake
    # -------------------------------------------------------------------------
    def is_handshake_completed(self, user_a: str, user_b: str) -> bool:
        """Verifica se o handshake E2EE já foi concluído entre esta dupla de amigos."""
        user_a = user_a.strip().lower()
        user_b = user_b.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT handshake_completed
                FROM friendships
                WHERE ((requester_username = ? AND addressee_username = ?)
                    OR (requester_username = ? AND addressee_username = ?))
                  AND status = 'ACCEPTED'
                LIMIT 1
                """,
                (user_a, user_b, user_b, user_a),
            )
            row = cursor.fetchone()
            return bool(row and row["handshake_completed"])

    def mark_handshake_completed(self, user_a: str, user_b: str) -> None:
        """Marca permanentemente que o handshake entre os dois amigos foi concluído."""
        user_a = user_a.strip().lower()
        user_b = user_b.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE friendships
                SET handshake_completed = 1, updated_at = CURRENT_TIMESTAMP
                WHERE ((requester_username = ? AND addressee_username = ?)
                    OR (requester_username = ? AND addressee_username = ?))
                  AND status = 'ACCEPTED'
                """,
                (user_a, user_b, user_b, user_a),
            )
            conn.commit()

    # -------------------------------------------------------------------------
    # Fila de Mensagens Offline (Store-and-Forward)
    # -------------------------------------------------------------------------
    def save_offline_message(self, recipient: str, sender: str, envelope_json: str, envelope_type: str = "") -> None:
        recipient = recipient.strip().lower()
        sender = sender.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            # Se for pacote de handshake, substitui eventual handshake anterior pendente do mesmo remetente
            # para evitar que o destinatário receba múltiplos KEY_EXCHANGE_INIT ao ficar online
            if envelope_type in ("KEY_EXCHANGE_INIT", "KEY_EXCHANGE_REPLY"):
                cursor.execute(
                    """
                    DELETE FROM offline_messages
                    WHERE recipient_username = ?
                      AND sender_username = ?
                      AND json_extract(envelope_json, '$.type') = ?
                    """,
                    (recipient, sender, envelope_type),
                )
            cursor.execute(
                """
                INSERT INTO offline_messages (recipient_username, sender_username, envelope_json)
                VALUES (?, ?, ?)
                """,
                (recipient, sender, envelope_json),
            )
            conn.commit()

    def pop_offline_messages(self, recipient: str) -> list[str]:
        recipient = recipient.strip().lower()
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, envelope_json
                FROM offline_messages
                WHERE recipient_username = ?
                ORDER BY id ASC
                """,
                (recipient,),
            )
            rows = cursor.fetchall()
            if rows:
                ids = [row["id"] for row in rows]
                placeholders = ",".join("?" for _ in ids)
                cursor.execute(
                    f"DELETE FROM offline_messages WHERE id IN ({placeholders})",
                    ids,
                )
                conn.commit()
            return [row["envelope_json"] for row in rows]


