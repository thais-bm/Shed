# src/backend/audit.py
import sys
from datetime import datetime


class SecurityAuditor:
    _history: list[dict] = []

    @classmethod
    def log_step(cls, module: str, action: str, details: str = "") -> None:
        """
        Imprime um log estruturado para a auditoria acadêmica do sistema
        e registra no histórico em memória para consulta na rota /chat/audit-log.
        """
        time_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Códigos ANSI para destacar cada módulo no terminal
        colors = {
            "AUTH": "\033[96m",     # Ciano
            "ECDH": "\033[94m",     # Azul
            "ECDSA": "\033[91m",    # Vermelho
            "SERPENT": "\033[92m",  # Verde
            "STORAGE": "\033[93m",  # Amarelo
            "API": "\033[95m",      # Roxo
            "ENDC": "\033[0m",      # Reset
        }

        color = colors.get(module.upper(), "\033[97m")

        encoding = sys.stdout.encoding or "utf-8"
        safe_action = action.encode(encoding, errors="replace").decode(encoding)
        print(f"[{time_now}] {color}[{module.upper()}]{colors['ENDC']} {safe_action}")
        if details:
            safe_details = details.encode(encoding, errors="replace").decode(encoding)
            for line in safe_details.splitlines():
                print(f" +-- {line}")

        cls._history.append(
            {
                "timestamp": time_now,
                "module": module.upper(),
                "action": action,
                "details": details,
            }
        )
        if len(cls._history) > 200:
            cls._history.pop(0)

    @classmethod
    def get_history(cls) -> list[dict]:
        return list(cls._history)