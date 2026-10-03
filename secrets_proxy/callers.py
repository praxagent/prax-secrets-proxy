"""Per-program identities for the forward proxy — so egress rules can differ by program.

Idea credit: NVIDIA OpenShell, whose network policy is per program (which
binary may reach which host).

Off unless ``PROXY_FORWARD_CALLERS`` names a callers file::

    {"callers": {
       "sandbox-shell": {"token_sha256": "9f86d08…"},
       "sandbox-browser": {"token_sha256": "60303ae…"}}}

Each program gets its OWN proxy token and presents it the usual way
(``HTTPS_PROXY=http://<name>:<token>@proxy:8788``). The file holds only
hashes, so it is not a secret. A request's identity is the name whose token it
presented — never the free-form Basic username, which any holder of any token
can set to anything. The main ``PROXY_FORWARD_AUTH_TOKEN`` keeps working and
identifies as ``PROXY_FORWARD_AUTH_NAME`` (default ``prax``).

Egress rules with ``"callers": [...]`` then apply only to those identities
(see ``egress_policy``). The strongest use is the credential itself: allow
``api.openai.com`` for ``prax`` only, and no other program can spend the key.

Honest limit: an identity is as separate as the token is. Programs that share
an environment (one container, one user) can read each other's tokens, so
this separates *components* — the harness, the sandbox shell, the browser —
not processes inside one of them. Attributing each connection to the binary
that opened it (OpenShell's supervisor does this) is the stronger form and is
not built here.

    python -m secrets_proxy.callers new NAME   # prints a token and its hash
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets

_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Callers:
    """Token → identity. Constant-time over every entry, whichever matches."""

    def __init__(self, main_token: str = "", main_name: str = "prax",
                 hashed: dict[str, str] | None = None):
        self.main_token = main_token
        self.main_name = main_name
        self.hashed = dict(hashed or {})
        for name in [main_name, *self.hashed]:
            if not _NAME.match(name):
                raise ValueError(f"caller name {name!r}: lowercase letters, digits, . _ - (max 40)")
        if main_token and main_name in self.hashed:
            raise ValueError(f"caller {main_name!r} is both the main token and in the callers file")

    @property
    def required(self) -> bool:
        """Is any credential configured? If not, the proxy runs open (and says so)."""
        return bool(self.main_token or self.hashed)

    def identify(self, presented: str) -> str | None:
        """The identity whose token was presented, or None if it matches none."""
        if not presented:
            return None
        found = None
        if self.main_token and hmac.compare_digest(presented, self.main_token):
            found = self.main_name
        d = digest(presented)
        for name, want in self.hashed.items():
            if hmac.compare_digest(d, want) and found is None:
                found = name
        return found

    @classmethod
    def from_env(cls) -> Callers:
        hashed: dict[str, str] = {}
        path = os.environ.get("PROXY_FORWARD_CALLERS", "")
        if path:
            with open(path) as f:
                data = json.load(f)
            for name, entry in (data.get("callers") or {}).items():
                want = str((entry or {}).get("token_sha256", "")).lower()
                if not re.fullmatch(r"[0-9a-f]{64}", want):
                    raise ValueError(f"caller {name!r}: token_sha256 must be 64 hex characters")
                hashed[str(name)] = want
        return cls(os.environ.get("PROXY_FORWARD_AUTH_TOKEN") or "",
                   os.environ.get("PROXY_FORWARD_AUTH_NAME") or "prax", hashed)


def _cli(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "new" or not _NAME.match(argv[1]):
        print("usage: python -m secrets_proxy.callers new NAME   (lowercase, digits, . _ -)")
        return 2
    token = secrets.token_urlsafe(32)
    print(f"token (give it to {argv[1]} only; it is not stored anywhere): {token}")
    print(f'callers file entry: "{argv[1]}": {{"token_sha256": "{digest(token)}"}}')
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
