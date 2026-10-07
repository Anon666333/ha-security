"""Validate native dashboard YAML and render its discovery template."""

from pathlib import Path
from types import SimpleNamespace
import unittest

from jinja2 import Environment, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def test_native_cards_dynamic_discovery_and_empty_state(self):
        config = yaml.safe_load((ROOT / "dashboards/security.yaml").read_text())
        cards = config["views"][0]["cards"]
        self.assertTrue(all(card["type"] == "markdown" for card in cards))
        template = Environment(undefined=StrictUndefined).from_string(cards[1]["content"])
        empty = template.render(states=SimpleNamespace(sensor=[]))
        self.assertIn("No HA Security user sensors", empty)
        user = SimpleNamespace(
            name="HA Security Matt Refresh tokens", state="12",
            attributes={"ha_security_metric": "refresh_tokens", "is_active": True,
                        "recently_observed": True},
        )
        unrelated = SimpleNamespace(
            name="Unrelated", state="1", attributes={"unrelated": True},
        )
        content = template.render(states=SimpleNamespace(sensor=[user, unrelated]))
        self.assertIn("Matt", content)
        self.assertIn("**12**", content)
        self.assertNotIn("Unrelated", content)

    def test_action_definitions_match_registered_actions(self):
        config = yaml.safe_load((ROOT / "custom_components/ha_security/services.yaml").read_text())
        self.assertEqual(set(config), {"query_audit", "get_inventory", "scan_now"})
