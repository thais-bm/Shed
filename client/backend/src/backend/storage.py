# client/backend/src/backend/storage.py
import sqlite3
from pathlib import Path
from .audit import SecurityAuditor


class LocalStorage:
    def __init__(self, owner_username: str):
        """
        Cada usuário rodando o cliente local terá seu próprio banco de dados.
        Ex: data/alice_history.db
        """
        self.owner = owner_username

        # Cria a pasta 'data' na raiz do backend, se não existir
        db_dir = Path("data")
        db_dir.mkdir(exist_ok=True)

        self.db_path = db_dir / f"{self.owner}_history.db"
        self._init_db()

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
            conn.commit()
        SecurityAuditor.log_step("STORAGE", "Banco de dados local inicializado.", f"Arquivo: {self.db_path}")

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
                (contact_username, is_sender, content)
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
                (contact_username,)
            )
            rows = cursor.fetchall()

        return [dict(row) for row in rows]