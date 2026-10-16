# server/src/server/audit.py
import sys
from datetime import datetime


class RelayAuditor:
    """
    Auditor visual do Servidor Relé para demonstração acadêmica.
    Destaca no terminal tudo o que trafega pela rede central (Handshakes ECDH,
    Assinaturas ECDSA, Pacotes Cifrados Serpent + HMAC e Fila Offline),
    comprovando que o servidor opera em modo Zero-Knowledge (não vê o texto limpo).
    """

    _history: list[dict] = []

    @classmethod
    def log_step(cls, module: str, action: str, details: str = "") -> None:
        time_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        colors = {
            "AUTH": "\033[95m",      # Roxo
            "FRIENDS": "\033[96m",   # Ciano
            "WS": "\033[94m",        # Azul
            "HANDSHAKE": "\033[93m", # Amarelo
            "E2EE-REDE": "\033[92m", # Verde
            "OFFLINE": "\033[91m",   # Vermelho/Coral
            "ENDC": "\033[0m",       # Reset
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
    def log_envelope_in_transit(cls, envelope: dict, delivered_online: bool) -> None:
        """
        Exibe um raio-X didático do envelope que está passando pelo Servidor Relé.
        """
        tipo = envelope.get("type", "UNKNOWN")
        remetente = envelope.get("from", "?")
        destinatario = envelope.get("to", "?")
        destino_status = "ENTREGUE EM TEMPO REAL (WebSocket)" if delivered_online else "GUARDADO NA FILA OFFLINE (Store-and-Forward)"

        if tipo in ("KEY_EXCHANGE_INIT", "KEY_EXCHANGE_REPLY"):
            pub_key = str(envelope.get("public_key", ""))
            lines = [line for line in pub_key.splitlines() if not line.startswith("---")]
            pub_preview = lines[0][:28] + "..." if lines else "N/A"
            sig_hex = str(envelope.get("signature", ""))
            sig_preview = sig_hex[:28] + "..." if sig_hex else "Sem assinatura"

            details = (
                f"Tráfego       : {remetente} -> {destinatario} ({destino_status})\n"
                f"Chave Efêmera : {pub_preview} (Curva SECP384R1)\n"
                f"Assinatura    : {sig_preview} (ECDSA-SHA256)"
            )
            cls.log_step("HANDSHAKE", f"Pacote '{tipo}' roteado pelo Relé.", details)

        elif tipo == "CHAT_MESSAGE":
            payload_hex = str(envelope.get("payload", ""))
            # Estrutura: [16 bytes IV (32 hex)] + [Ciphertext Serpent] + [32 bytes HMAC (64 hex)]
            iv_hex = payload_hex[:32]
            mac_hex = payload_hex[-64:] if len(payload_hex) >= 96 else ""
            cipher_hex = payload_hex[32:-64] if len(payload_hex) >= 96 else payload_hex

            details = (
                f"Tráfego            : {remetente} -> {destinatario} ({destino_status})\n"
                f"IV (16 bytes)      : {iv_hex}\n"
                f"Cifra Serpent (CBC): {cipher_hex[:40]}... ({len(cipher_hex) // 2} bytes cifrados)\n"
                f"Lacre HMAC-SHA256  : {mac_hex[:40]}...\n"
                f"Texto Limpo no Relé: [ILEGÍVEL / ZERO-KNOWLEDGE - Relé não possui a chave simétrica!]"
            )
            cls.log_step("E2EE-REDE", "Mensagem cifrada atravessando o Servidor Relé!", details)

    @classmethod
    def get_history(cls) -> list[dict]:
        return list(cls._history)
