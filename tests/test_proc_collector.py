import sys
import unittest
from unittest.mock import patch

from scripts import tracegate_proc_collector as collector


class ProcCollectorPlatformTests(unittest.TestCase):
    def test_snapshot_rejects_non_linux_before_accessing_procfs(self):
        with patch.object(sys, "platform", "win32"):
            with self.assertRaisesRegex(OSError, "requires Linux /proc"):
                collector.snapshot(123, ["Filetop__Total_Reads"])

    def test_command_rejects_non_linux_before_calling_the_api(self):
        with patch.object(sys, "platform", "win32"), patch.object(sys, "argv", ["tracegate_proc_collector.py"]):
            with patch.object(collector, "get_json") as get_json:
                with self.assertRaisesRegex(SystemExit, "requires Linux /proc"):
                    collector.main()
                get_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
