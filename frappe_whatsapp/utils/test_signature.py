import hashlib
import hmac
import unittest

from frappe_whatsapp.utils.signature import is_valid_meta_signature

BODY = b'{"object":"whatsapp_business_account","entry":[]}'


def sign(body, secret):
	return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestMetaSignature(unittest.TestCase):
	def test_valid_signature(self):
		self.assertTrue(is_valid_meta_signature(BODY, sign(BODY, "s3cret"), ["s3cret"]))

	def test_any_of_several_accounts(self):
		self.assertTrue(is_valid_meta_signature(BODY, sign(BODY, "two"), ["one", None, "two"]))

	def test_wrong_secret(self):
		self.assertFalse(is_valid_meta_signature(BODY, sign(BODY, "attacker"), ["s3cret"]))

	def test_tampered_body(self):
		self.assertFalse(is_valid_meta_signature(BODY + b" ", sign(BODY, "s3cret"), ["s3cret"]))

	def test_missing_or_malformed_header(self):
		for header in (None, "", "sha1=abc", sign(BODY, "s3cret")[7:]):
			self.assertFalse(is_valid_meta_signature(BODY, header, ["s3cret"]))

	def test_no_secret_configured_rejects(self):
		self.assertFalse(is_valid_meta_signature(BODY, sign(BODY, ""), []))
		self.assertFalse(is_valid_meta_signature(BODY, sign(BODY, "x"), [None, ""]))

	def test_uppercase_hex_accepted(self):
		self.assertTrue(is_valid_meta_signature(BODY, sign(BODY, "s3cret").upper().replace("SHA256=", "sha256="), ["s3cret"]))


if __name__ == "__main__":
	unittest.main()
