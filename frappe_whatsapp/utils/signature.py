"""Meta webhook signature check (X-Hub-Signature-256).

Meta signs every webhook POST with HMAC-SHA256 of the raw request body, keyed by the App Secret
of the Meta app: header value ``sha256=<hex digest>``. No frappe import, so it is testable alone.
"""

import hashlib
import hmac


def is_valid_meta_signature(raw_body, header, app_secrets):
	"""True when ``header`` is a valid signature of ``raw_body`` for any of ``app_secrets``."""
	if not header or not header.startswith("sha256="):
		return False
	received = header[len("sha256=") :].strip().lower()
	if isinstance(raw_body, str):
		raw_body = raw_body.encode()
	for secret in app_secrets:
		if not secret:
			continue
		expected = hmac.new(secret.encode(), raw_body or b"", hashlib.sha256).hexdigest()
		if hmac.compare_digest(received, expected):
			return True
	return False
