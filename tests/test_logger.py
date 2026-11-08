"""Unit tests for falak.utils.logger, focused on secret redaction."""

from __future__ import annotations

import io
import logging
import unittest

from falak.utils.logger import RedactingFilter, get_logger, redact_secrets

# A syntactically valid-shaped WireGuard key for test purposes only:
# 43 base64 characters + '=' padding (44 total). Not a real key.
FAKE_KEY = "yAnz5TF8lXXJte14tji3zlMNq8hd2rYUIgJBgB3fBm" + "k="


class TestRedactSecrets(unittest.TestCase):
    def test_private_key_line_is_redacted(self) -> None:
        text = f"PrivateKey = {FAKE_KEY}"
        self.assertNotIn(FAKE_KEY, redact_secrets(text))
        self.assertIn("[REDACTED]", redact_secrets(text))

    def test_preshared_key_line_is_redacted(self) -> None:
        text = f"PresharedKey={FAKE_KEY}"
        self.assertNotIn(FAKE_KEY, redact_secrets(text))

    def test_key_line_is_case_insensitive(self) -> None:
        text = f"privatekey = {FAKE_KEY}"
        self.assertNotIn(FAKE_KEY, redact_secrets(text))

    def test_bare_key_pattern_outside_a_labeled_line_is_redacted(self) -> None:
        text = f"unexpected key in output: {FAKE_KEY} (end)"
        self.assertNotIn(FAKE_KEY, redact_secrets(text))

    def test_non_secret_text_is_unchanged(self) -> None:
        text = "Interface: wg0, status: up, handshake: 12s ago"
        self.assertEqual(redact_secrets(text), text)

    def test_empty_string_is_unchanged(self) -> None:
        self.assertEqual(redact_secrets(""), "")

    def test_public_endpoint_line_is_not_falsely_redacted(self) -> None:
        text = "Endpoint = 203.0.113.5:51820"
        self.assertEqual(redact_secrets(text), text)


class TestRedactingFilter(unittest.TestCase):
    def test_filter_redacts_record_message(self) -> None:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="PrivateKey = %s",
            args=(FAKE_KEY,),
            exc_info=None,
        )
        filt = RedactingFilter()
        result = filt.filter(record)
        self.assertTrue(result)
        self.assertNotIn(FAKE_KEY, record.getMessage())
        self.assertIn("[REDACTED]", record.getMessage())


class TestGetLogger(unittest.TestCase):
    def test_logger_output_does_not_contain_secret(self) -> None:
        logger = get_logger("falak.test.redaction")

        stream = io.StringIO()
        test_handler = logging.StreamHandler(stream)
        test_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(test_handler)
        try:
            logger.info("PrivateKey = %s", FAKE_KEY)
        finally:
            logger.removeHandler(test_handler)

        output = stream.getvalue()
        self.assertNotIn(FAKE_KEY, output)
        self.assertIn("[REDACTED]", output)

    def test_get_logger_does_not_duplicate_handlers(self) -> None:
        logger_a = get_logger("falak.test.singleton")
        logger_b = get_logger("falak.test.singleton")
        self.assertIs(logger_a, logger_b)
        self.assertEqual(len(logger_a.handlers), 1)

    def test_logger_does_not_propagate_to_root(self) -> None:
        logger = get_logger("falak.test.propagation")
        self.assertFalse(logger.propagate)


if __name__ == "__main__":
    unittest.main()
