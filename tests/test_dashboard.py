"""Dashboard wiring and published action definitions."""
from pathlib import Path
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[1]
class DashboardTests(unittest.TestCase):
    def test_dashboard_uses_bundled_entity_card(self):
        config = yaml.safe_load((ROOT / "dashboards/security.yaml").read_text())
        self.assertEqual(config["views"][0]["cards"][0]["type"], "custom:ha-security-card")
        self.assertTrue((ROOT / "custom_components/ha_security/www/ha-security-card.js").is_file())
    def test_action_definitions_match_registered_actions(self):
        config = yaml.safe_load((ROOT / "custom_components/ha_security/services.yaml").read_text())
        self.assertEqual(set(config), {"query_audit", "get_inventory", "scan_now", "set_token_label", "query_sessions", "recognize_source"})
