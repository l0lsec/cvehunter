"""Tests for Docker operations helpers."""

from __future__ import annotations

import yaml

from cvehunter.agents.builder import _strip_host_ports
from cvehunter.tools.docker_ops import _force_internal_networks


class TestForceInternalNetworks:
    def test_no_networks_section_adds_internal_default(self):
        compose = "services:\n  web:\n    image: vuln:1.0\n"
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["default"]["internal"] is True

    def test_declared_network_without_internal_is_forced(self):
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    networks: [vuln-net]\n"
            "networks:\n  vuln-net: {}\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["vuln-net"]["internal"] is True
        # No spurious default network when every service is explicitly attached.
        assert "default" not in doc["networks"]

    def test_null_network_config_is_forced(self):
        # ``vuln-net:`` with no mapping parses to None — must still get internal.
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    networks: [vuln-net]\n"
            "networks:\n  vuln-net:\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["vuln-net"]["internal"] is True

    def test_internal_true_is_preserved(self):
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    networks: [vuln-net]\n"
            "networks:\n  vuln-net:\n    internal: true\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["vuln-net"]["internal"] is True

    def test_external_network_left_untouched(self):
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    networks: [ext]\n"
            "networks:\n  ext:\n    external: true\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["ext"].get("external") is True
        assert "internal" not in doc["networks"]["ext"]

    def test_service_without_networks_key_gets_internal_default(self):
        # web is explicit on vuln-net; db has no networks key -> joins default.
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    networks: [vuln-net]\n"
            "  db:\n    image: postgres:15\n"
            "networks:\n  vuln-net: {}\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["vuln-net"]["internal"] is True
        assert doc["networks"]["default"]["internal"] is True

    def test_multi_service_compose_all_networks_internal(self):
        compose = (
            "services:\n"
            "  web:\n    build: .\n    networks: [vuln-net]\n"
            "  db:\n    image: postgres:15\n    networks: [vuln-net]\n"
            "networks:\n  vuln-net: {}\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["networks"]["vuln-net"]["internal"] is True
        # Every service stays attached to the (now internal) network.
        assert doc["services"]["web"]["networks"] == ["vuln-net"]
        assert doc["services"]["db"]["networks"] == ["vuln-net"]

    def test_ports_are_not_stripped(self):
        # Isolation must not remove published ports — only egress is blocked.
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    ports: ['8080:80']\n"
            "    networks: [vuln-net]\n"
            "networks:\n  vuln-net: {}\n"
        )
        doc = yaml.safe_load(_force_internal_networks(compose))
        assert doc["services"]["web"]["ports"] == ["8080:80"]
        assert doc["networks"]["vuln-net"]["internal"] is True

    def test_invalid_yaml_returned_unchanged(self):
        bad = "services: [unclosed"
        assert _force_internal_networks(bad) == bad

    def test_no_services_returned_unchanged(self):
        nosvc = "version: '3'\n"
        assert _force_internal_networks(nosvc) == nosvc

    def test_idempotent_after_strip_host_ports(self):
        # The patched env runs _strip_host_ports then compose_up's internal pass.
        compose = (
            "services:\n"
            "  web:\n    image: vuln:1.0\n    ports: ['8080:80']\n"
            "    networks: [vuln-net]\n"
            "networks:\n  vuln-net: {}\n"
        )
        stripped = _strip_host_ports(compose)
        doc = yaml.safe_load(_force_internal_networks(stripped))
        assert "ports" not in doc["services"]["web"]
        assert doc["networks"]["vuln-net"]["internal"] is True
