# api-key-misconfig-scanner
Slayer GAPIs Scanner is a focused security assessment tool designed to detect misconfigured, overly permissive, or abusable Google API keys by validating real-world access across multiple Google services.

Unlike simple key validators, this tool classifies API key behavior to distinguish between:
invalid or revoked keys
valid keys with disabled APIs
quota-exhausted keys
restricted keys (IP / referer limited)
keys that allow successful, billable API access

The scanner interacts with actual Google API endpoints and evaluates responses semantically rather than relying solely on HTTP status codes, reducing false positives and false negatives commonly seen in automated checks.
