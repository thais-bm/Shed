# server/src/server/audit.py
import hashlib
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

    _COLORS = {
        "AUTH": "\033[95m",       # Roxo
        "FRIENDS": "\033[96m",    # Ciano
        "WS": "\033[94m",         # Azul
        "HANDSHAKE": "\033[93m",  # Amarelo
        "E2EE-REDE": "\033[92m",  # Verde
        "OFFLINE": "\033[91m",    # Vermelho/Coral
        "FASE": "\033[1;97m",     # Branco negrito - cabeçalhos de seção
        "ENDC": "\033[0m",        # Reset
    }

    @staticmethod
    def fingerprint(data: bytes | str) -> str:
        """
        Impressão digital curta (SHA-256, 8 bytes). Usa o mesmo cálculo do cliente: a impressão digital
        de uma chave pública vista aqui deve ser IDÊNTICA à exibida no terminal do cliente que a enviou.
        """
        raw = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(raw).hexdigest()[:16].upper()
        return " ".join(digest[i : i + 4] for i in range(0, 16, 4))

    @staticmethod
    def _safe(text: str) -> str:
        encoding = sys.stdout.encoding or "utf-8"
        return text.encode(encoding, errors="replace").decode(encoding)

    @classmethod
    def banner(cls, title: str, subtitle: str = "") -> None:
        """Cabeçalho de seção para separar visualmente cada etapa da apresentação."""
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
            sig_hex = str(envelope.get("signature", ""))
            sig_preview = sig_hex[:32] + "..." if sig_hex else "Sem assinatura"
            fingerprint = cls.fingerprint(pub_key) if pub_key else "N/A"

            details = (
                f"Tráfego            : {remetente} -> {destinatario} ({destino_status})\n"
                f"Chave efêmera ECDH : fingerprint {fingerprint} (curva SECP384R1, só a parte PÚBLICA)\n"
                f"Assinatura         : {sig_preview} (ECDSA-SHA256, feita com a chave de identidade de '{remetente}')\n"
                f"O que o Relé vê    : chaves públicas e assinaturas. NUNCA chaves privadas nem a chave de sessão.\n"
                f"Confira            : este fingerprint deve ser igual ao exibido no terminal de '{remetente}'."
            )
            titulo = "INICIANDO" if tipo == "KEY_EXCHANGE_INIT" else "RESPONDENDO"
            cls.log_step("HANDSHAKE", f"{titulo} troca de chaves: '{tipo}' roteado pelo Relé.", details)

        elif tipo == "CHAT_MESSAGE":
            payload_hex = str(envelope.get("payload", ""))
            # Estrutura: [16 bytes IV (32 hex)] + [Ciphertext Serpent] + [32 bytes HMAC (64 hex)]
            iv_hex = payload_hex[:32]
            mac_hex = payload_hex[-64:] if len(payload_hex) >= 96 else ""
            cipher_hex = payload_hex[32:-64] if len(payload_hex) >= 96 else payload_hex

            details = (
                f"Tráfego             : {remetente} -> {destinatario} ({destino_status})\n"
                f"Pacote total        : {len(payload_hex) // 2} bytes = IV 16 + cifra {len(cipher_hex) // 2} + HMAC 32\n"
                f"IV (16 bytes)       : {iv_hex}\n"
                f"Cifra Serpent (CBC) : {cipher_hex[:40]}...\n"
                f"Lacre HMAC-SHA256   : {mac_hex[:40]}...\n"
                f"Dentro da cifra     : texto + seq + timestamp (anti-replay). O Relé não consegue ler nem forjar.\n"
                f"Texto limpo no Relé : [ILEGÍVEL / ZERO-KNOWLEDGE - o Relé não possui a chave simétrica!]"
            )
            cls.log_step("E2EE-REDE", "Mensagem cifrada atravessando o Servidor Relé!", details)

    @classmethod
    def get_history(cls) -> list[dict]:
        return list(cls._history)
