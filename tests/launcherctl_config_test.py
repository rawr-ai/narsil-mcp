import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHERCTL_PATH = REPO_ROOT / "scripts" / "launcherctl.py"


spec = importlib.util.spec_from_file_location("launcherctl", LAUNCHERCTL_PATH)
launcherctl = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["launcherctl"] = launcherctl
spec.loader.exec_module(launcherctl)


class LauncherConfigTests(unittest.TestCase):
    def parse_config(self, content: str):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(textwrap.dedent(content))
            path = Path(f.name)
        try:
            return launcherctl.parse_launcher_config(path)
        finally:
            path.unlink(missing_ok=True)

    def test_defaults_to_voyage_code_3(self):
        instances = self.parse_config(
            """
            version = 1

            [[instances]]
            id = "magic-api"
            label = "com.rawr.narsil-mcp-magic-api"
            port = 12007
            repos = ["/tmp/repo"]
            """
        )

        self.assertEqual(instances[0].neural_model, "voyage-code-3")

    def test_supports_global_and_per_instance_model(self):
        instances = self.parse_config(
            """
            version = 1
            default_neural_model = "voyage-code-3"

            [[instances]]
            id = "a"
            label = "com.rawr.narsil-mcp-a"
            port = 12006
            repos = ["/tmp/a"]

            [[instances]]
            id = "b"
            label = "com.rawr.narsil-mcp-b"
            port = 12007
            neural_model = "voyage-code-2"
            repos = ["/tmp/b"]
            """
        )

        self.assertEqual(instances[0].neural_model, "voyage-code-3")
        self.assertEqual(instances[1].neural_model, "voyage-code-2")


if __name__ == "__main__":
    unittest.main()
