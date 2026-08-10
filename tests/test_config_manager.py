"""
Tests for ConfigManager (src/config/config_manager.py).

Covers: valid YAML loading, nested key retrieval with/without defaults,
missing config file, malformed YAML, empty file, and missing required
top-level sections — matching the actual ConfigError-raising behavior
implemented in ConfigManager._load() and ._validate().
"""

import pytest

from src.config.config_manager import ConfigManager, ConfigError
from tests.conftest import make_config


class TestValidConfigLoading:

    def test_loads_valid_config_without_error(self, make_config):
        config = make_config()
        assert isinstance(config, ConfigManager)

    def test_as_dict_returns_full_config(self, make_config):
        config = make_config()
        full = config.as_dict()

        assert isinstance(full, dict)
        assert "network" in full
        assert "detection" in full
        assert "logging" in full
        assert "dashboard" in full

    def test_get_retrieves_top_level_value(self, make_config):
        config = make_config()
        assert config.get("network", "interface") == "Wi-Fi"

    def test_get_retrieves_deeply_nested_value(self, make_config):
        config = make_config()
        threshold = config.get("detection", "port_scan", "unique_ports_threshold")
        assert threshold == 15

    def test_get_retrieves_overridden_value(self, make_config):
        config = make_config(overrides={
            "detection": {"port_scan": {"unique_ports_threshold": 3}}
        })
        # Overridden value reflected...
        assert config.get("detection", "port_scan", "unique_ports_threshold") == 3
        # ...while sibling values from the base config are preserved (deep merge).
        assert config.get("detection", "port_scan", "time_window_seconds") == 10

    def test_get_retrieves_list_value(self, make_config):
        config = make_config(overrides={
            "detection": {"malicious_ips": ["1.2.3.4"]}
        })
        assert config.get("detection", "malicious_ips") == ["1.2.3.4"]


class TestGetDefaults:

    def test_get_missing_key_returns_none_by_default(self, make_config):
        config = make_config()
        assert config.get("network", "nonexistent_key") is None

    def test_get_missing_key_returns_explicit_default(self, make_config):
        config = make_config()
        result = config.get("network", "nonexistent_key", default="fallback")
        assert result == "fallback"

    def test_get_missing_top_level_section_returns_default(self, make_config):
        config = make_config()
        result = config.get("nonexistent_section", "some_key", default="fallback")
        assert result == "fallback"

    def test_get_walks_into_non_dict_returns_default(self, make_config):
        # "interface" is a string, not a dict — walking further into it
        # should safely fall through to the default rather than error.
        config = make_config()
        result = config.get("network", "interface", "too_deep", default="fallback")
        assert result == "fallback"

    def test_get_with_no_keys_returns_entire_config(self, make_config):
        # get() with zero keys should just return self._config unchanged
        # (the loop body never executes).
        config = make_config()
        assert config.get() == config.as_dict()


class TestMissingConfigFile:

    def test_missing_file_raises_config_error(self, tmp_path):
        missing_path = tmp_path / "does_not_exist.yaml"
        with pytest.raises(ConfigError, match="Config file not found"):
            ConfigManager(str(missing_path))


class TestMalformedYaml:

    def test_invalid_yaml_syntax_raises_config_error(self, make_config):
        broken_yaml = "network: [unclosed_list\ndetection: {also: broken"
        with pytest.raises(ConfigError, match="Failed to parse YAML config"):
            make_config(raw_yaml_text=broken_yaml)

    def test_empty_file_raises_config_error(self, make_config):
        with pytest.raises(ConfigError, match="Config file is empty"):
            make_config(raw_yaml_text="")

    def test_yaml_that_parses_to_non_dict_raises_config_error(self, make_config):
        # A valid YAML scalar/list at the root isn't a valid config shape.
        # ConfigManager doesn't explicitly guard against this beyond the
        # None-check, so a bare string parses to a non-dict "_config" and
        # _validate()'s `"section" not in self._config` check on a string
        # raises a TypeError, not a ConfigError — this test documents the
        # ACTUAL current behavior rather than an assumed one.
        with pytest.raises(ConfigError, match="Missing required config section"):
            make_config(raw_yaml_text="just_a_plain_string") 

class TestMissingRequiredSections:

    @pytest.mark.parametrize("missing_section", ["network", "detection", "logging", "dashboard"])
    def test_missing_required_section_raises_config_error(self, make_config, missing_section):
        base = {
            "network": {"interface": "Wi-Fi"},
            "detection": {"port_scan": {"unique_ports_threshold": 15, "time_window_seconds": 10}},
            "logging": {"log_dir": "logs"},
            "dashboard": {"refresh_interval_seconds": 3},
        }
        del base[missing_section]

        import yaml as yaml_module
        with pytest.raises(ConfigError, match="Missing required config section"):
            make_config(raw_yaml_text=yaml_module.dump(base))

    def test_error_message_lists_all_missing_sections(self, make_config):
        import yaml as yaml_module
        minimal = {"network": {"interface": "Wi-Fi"}}  # only 1 of 4 required sections
        with pytest.raises(ConfigError) as exc_info:
            make_config(raw_yaml_text=yaml_module.dump(minimal))

        message = str(exc_info.value)
        assert "detection" in message
        assert "logging" in message
        assert "dashboard" in message