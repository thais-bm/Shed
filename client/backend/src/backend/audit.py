# src/backend/audit.py
import hashlib
import sys
from datetime import datetime


class SecurityAuditor:
    _history: list[dict] = []

    # Códigos ANSI para destacar cada módulo no terminal
    _COLORS = {
        "AUTH": "\033[96m",       # Ciano     - senha / Split-Key / login
        "ECDH": "\033[94m",       # Azul      - chaves efêmeras e segredo compartilhado
        "ECDSA": "\033[91m",      # Vermelho  - identidade e assinaturas
        "HANDSHAKE": "\033[93m",  # Amarelo   - troca de chaves entre contatos
        "TOFU": "\033[33m",       # Laranja   - fixação da identidade do contato
        "SERPENT": "\033[92m",    # Verde     - cifragem / HMAC
        "REPLAY": "\033[35m",     # Magenta   - proteção anti-replay
        "STORAGE": "\033[93m",    # Amarelo   - SQLite local
        "API": "\033[95m",        # Roxo      - rotas e eventos gerais
        "FASE": "\033[1;97m",     # Branco negrito - cabeçalhos de seção
        "ENDC": "\033[0m",        # Reset
    }

    @staticmethod
    def fingerprint(data: bytes | str) -> str:
        """
        Impressão digital curta (SHA-256, 8 bytes) para comparar chaves entre terminais
        sem expor o valor da chave. Ex.: 'A1B2 C3D4 E5F6 0718'.
        """
        raw = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(raw).hexdigest()[:16].upper()
        return " ".join(digest[i : i + 4] for i in range(0, 16, 4))

    @classmethod
    def _safe(cls, text: str) -> str:
        encoding = sys.stdout.encoding or "utf-8"
        return text.encode(encoding, errors="replace").decode(encoding)

    @classmethod
    def banner(cls, title: str, subtitle: str = "") -> None:
        """Cabeçalho de seção: separa visualmente cada etapa da apresentação no terminal."""
        width = 78
        bold = cls._COLORS["FASE"]
        end = cls._COLORS["ENDC"]
        print()
        print(f"{bold}{'=' * width}{end}")
        print(f"{bold}  {cls._safe(title)}{end}")
        if subtitle:
            print(f"  {cls._safe(subtitle)}")
        print(f"{bold}{'=' * width}{end}")
        cls._append("FASE", title, subtitle, datetime.now().strftime("%H:%M:%S.%f")[:-3])

    @classmethod
    def log_step(cls, module: str, action: str, details: str = "") -> None:
        """
        Imprime um log estruturado para a auditoria acadêmica do sistema
        e registra no histórico em memória para consulta na rota /chat/audit-log.
        """
        time_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        color = cls._COLORS.get(module.upper(), "\033[97m")

        print(f"[{time_now}] {color}[{module.upper()}]{cls._COLORS['ENDC']} {cls._safe(action)}")
        if details:
            for line in cls._safe(details).splitlines():
                print(f"      | {line}")

        cls._append(module.upper(), action, details, time_now)

    @classmethod
    def _append(cls, module: str, action: str, details: str, time_now: str) -> None:
        cls._history.append(
            {
                "timestamp": time_now,
                "module": module,
                "action": action,
                "details": details,
            }
        )
        if len(cls._history) > 200:
            cls._history.pop(0)

    @classmethod
    def get_history(cls) -> list[dict]:
        return list(cls._history)
