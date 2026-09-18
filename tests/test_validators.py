"""Unit tests for core.validators."""
import unittest
from core.validators import (
    ValidationError, sanitize_filename, validate_domain, validate_ip,
    validate_port_range, validate_threads, validate_timeout, validate_url,
)


class TestValidators(unittest.TestCase):
    def test_domain_ok(self):
        self.assertEqual(validate_domain("Example.COM."), "example.com")

    def test_domain_bad(self):
        for bad in ["", "-bad.com", "no_dot", "a..b.com", "x" * 300]:
            with self.assertRaises(ValidationError, msg=f"bad={bad!r}"):
                validate_domain(bad)

    def test_ip_ok(self):
        self.assertEqual(validate_ip("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_ip("::1"), "::1")

    def test_ip_bad(self):
        with self.assertRaises(ValidationError):
            validate_ip("999.1.1.1")

    def test_url_ok(self):
        self.assertEqual(validate_url("example.com"), "https://example.com")
        self.assertEqual(validate_url("http://x.test/a?b=1"), "http://x.test/a?b=1")

    def test_url_bad(self):
        for bad in ["ftp://x", "javascript:alert(1)", "http://", ""]:
            with self.assertRaises(ValidationError):
                validate_url(bad)

    def test_port_range(self):
        self.assertEqual(validate_port_range("22,80,8000-8002"),
                         [22, 80, 8000, 8001, 8002])

    def test_threads(self):
        self.assertEqual(validate_threads(10), 10)
        with self.assertRaises(ValidationError):
            validate_threads(0)

    def test_timeout(self):
        self.assertEqual(validate_timeout(1.5), 1.5)
        with self.assertRaises(ValidationError):
            validate_timeout(0)

    def test_sanitize(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "etc_passwd")


if __name__ == "__main__":
    unittest.main()
