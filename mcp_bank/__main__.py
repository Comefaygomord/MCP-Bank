"""Entry point: ``python -m mcp_bank``."""
from .config import settings
from .server import mcp

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=settings.host,
        port=settings.port,
        path="/mcp",
    )
