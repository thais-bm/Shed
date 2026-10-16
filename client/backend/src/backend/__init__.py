import sys


def main() -> None:
    """Atalho: `uv run backend [porta]` inicia a API local (porta padrão: 8001)."""
    import uvicorn

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    uvicorn.run("backend.api:app", host="127.0.0.1", port=port)
