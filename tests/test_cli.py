"""CLI smoke tests."""
import unittest
from core.cli import build_parser


class TestCLI(unittest.TestCase):
    def test_doctor(self):
        self.assertTrue(build_parser().parse_args(["--doctor"]).doctor)

    def test_info(self):
        self.assertEqual(
            build_parser().parse_args(["--info", "example.com"]).info,
            "example.com")

    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.timeout, 5.0)
        self.assertEqual(args.threads, 50)


if __name__ == "__main__":
    unittest.main()
