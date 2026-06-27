"""Entry point for the Atomic Red Team MCP server."""

from __future__ import annotations

import logging
import sys

import uvicorn

from atomic_mcp_server import __version__
from atomic_mcp_server.config import get_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("atomic_mcp_server.main")


def main() -> None:
    try:
        config = get_config()
        logger.info("Starting Atomic Red Team MCP Server v%s", __version__)
        logger.info("Server: http://%s:%s/mcp", config.mcp_host, config.mcp_port)
        logger.info("Target: %s via %s", config.allowed_target, config.transport)
        uvicorn.run(
            "atomic_mcp_server.server:app",
            host=config.mcp_host,
            port=config.mcp_port,
            log_level="info",
            access_log=True,
            server_header=False,
            date_header=False,
        )
    except Exception as exc:
        logger.error("Server error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
