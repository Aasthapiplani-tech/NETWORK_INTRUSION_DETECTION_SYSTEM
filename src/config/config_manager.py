"""
ConfigManager: Loads, validates, and provides access to the NIDS YAML configuration.
"""

import os
import yaml
import logging

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the configuration file is missing, malformed, or invalid."""
    pass


class ConfigManager:
    """
    Loads configuration from a YAML file and exposes it as a validated dictionary.

    Usage:
        config = ConfigManager("config/config.yaml")
        interface = config.get("network", "interface")
    """

    REQUIRED_SECTIONS = ["network", "detection", "logging", "dashboard"]

    def __init__(self, config_path: str):
        """
        Args:
            config_path: Path to the YAML config file.

        Raises:
            ConfigError: If the file doesn't exist or is invalid.
        """
        self.config_path = config_path
        self._config = {}
        self._load()
        self._validate()

    def _load(self):
        """Reads and parses the YAML file into memory."""
        if not os.path.exists(self.config_path):
            raise ConfigError(f"Config file not found: {self.config_path}")

        try:
            with open(self.config_path, "r") as f:
                self._config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigError(f"Failed to parse YAML config: {e}")

        if self._config is None:
            raise ConfigError("Config file is empty.")

    def _validate(self):
        """Ensures all required top-level sections exist."""
        missing = [s for s in self.REQUIRED_SECTIONS if s not in self._config]
        if missing:
            raise ConfigError(f"Missing required config section(s): {missing}")
        logger.info("Configuration loaded and validated successfully.")

    def get(self, *keys, default=None):
        """
        Retrieves a nested config value.

        Example:
            config.get("detection", "port_scan", "unique_ports_threshold")

        Args:
            *keys: Sequence of nested keys to walk into.
            default: Value returned if the key path doesn't exist.

        Returns:
            The config value, or `default` if not found.
        """
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def as_dict(self) -> dict:
        """Returns the entire config as a plain dictionary."""
        return self._config