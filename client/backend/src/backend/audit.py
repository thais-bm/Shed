# src/backend/audit.py
from datetime import datetime

class SecurityAuditor:
    @staticmethod
    def log_step(module: str, action: str, details: str = ""):
        """
        Imprime um log estruturado para a auditoria acadêmica do sistema.
        """
        time_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Códigos ANSI para destacar cada módulo no terminal
        colors = {
            "ECDH": "\033[94m",     # Azul
            "SERPENT": "\033[92m",  # Verde
            "STORAGE": "\033[93m",  # Amarelo
            "API": "\033[95m",      # Roxo
            "ENDC": "\033[0m"       # Reset
        }
        
        color = colors.get(module.upper(), "\033[97m")
        
        print(f"[{time_now}] {color}[{module.upper()}]{colors['ENDC']} {action}")
        if details:
            print(f" └── {details}")