import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
import mglru_postcall_ab as m


class Safety(TestCase):
    def test_block_during_first_ten_minutes_of_boot(self):
        with patch.object(m, 'shell', return_value='135.45 15.0'):
            with self.assertRaisesRegex(RuntimeError, 'first 10 minutes'):
                m.safe_preflight('mock', 0)

    def test_block_when_initial_not_zero(self):
        with patch.object(m, "lru_state", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "not 0"):
                m.trial("mock", 12, 3, Path("no-file-created.json"))

    def test_restores_after_candidate_failure(self):
        status = {"lru": 0}
        def setter(_, value):
            status["lru"] = value
            return value
        def getter(_):
            return status["lru"]
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)/"receipt.json"
            with patch.object(m, "lru_state", side_effect=getter), \
                 patch.object(m, "safe_preflight"), \
                 patch.object(m, "install_watchdog", return_value="1337"), \
                 patch.object(m, "set_lru", side_effect=setter) as write, \
                 patch.object(m, "stage", side_effect=[{"label": "A"}, RuntimeError("trial failed")]):
                with self.assertRaisesRegex(RuntimeError, "trial failed"):
                    m.trial("mock", 12, 3, dest)
                self.assertEqual(status["lru"], 0)
                self.assertTrue(dest.is_file())
                self.assertIn('"restored": true', dest.read_text())
                self.assertEqual([x.args[1] for x in write.call_args_list], [7, 0])

    def test_forbidden_values(self):
        with self.assertRaises(ValueError):
            m.set_lru("mock", 5)


if __name__ == "__main__":
    main()
