"""
Logging configuration for the NIDS system.
Sets up structured logging to both console and a rotating log file.
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_dir: str = "logs", log_file: str = "nids.log", log_level: str = "INFO"):
    """
    Configures the root logger for the entire application.

    Sets up two handlers:
      - Console handler: prints logs to the terminal (for live monitoring)
      - Rotating file handler: writes logs to disk, capped in size to avoid
        unbounded growth

    Args:
        log_dir: Directory where the log file will be written. Created if missing.
        log_file: Name of the log file.
        log_level: Minimum severity to log (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    Returns:
        The configured root logger.
    """
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)

    level = getattr(logging, log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=3  # 5MB per file, keep 3 backups
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if setup_logging() gets called more than once
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    root_logger.info("Logging initialized. Level=%s, File=%s", log_level.upper(), log_path)
    return root_logger