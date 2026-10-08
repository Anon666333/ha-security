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
        activity = SimpleNamespace(name="Matt Recently used tokens", state="2", attributes={
            "ha_security_metric": "recently_used_tokens", "recent_window_minutes": 15,
            "connections": [{"token_id": "record-a", "client_id": "mobile", "label": "Matt's phone",
                        "last_used_ip": "192.0.2.1", "recently_used": True}],
            "ip_observations": [{"token_id": "record-a", "last_used_ip": "192.0.2.2",
                                 "observed_at": "2026-10-07T10:00:00+00:00"}],
        })
        environment = Environment(undefined=StrictUndefined)
        environment.globals.update(as_datetime=lambda value, default=None: value, relative_time=lambda value: "2 minutes")
        detail_template = environment.from_string(cards[2]["content"])
        details = detail_template.render(states=SimpleNamespace(sensor=[activity]))
        self.assertIn("192.0.2.1", details)
        self.assertIn("192.0.2.2", details)
        self.assertIn("record-a", details)
        activity.attributes.pop("connections")
        self.assertIn("Enable", detail_template.render(states=SimpleNamespace(sensor=[activity])))

    def test_action_definitions_match_registered_actions(self):
        config = yaml.safe_load((ROOT / "custom_components/ha_security/services.yaml").read_text())
        self.assertEqual(set(config), {"query_audit", "get_inventory", "scan_now", "set_token_label"})
