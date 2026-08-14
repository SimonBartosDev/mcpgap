"""Canned upstream responses for sealed mode.

The sandbox never reaches a real API. Every request terminates here and gets a
plausible, **deterministic** reply. Three reasons, in order of importance:

1. We must not actually send anything. The package under test is malware whose
   payload is an email BCC'd to the attacker; forwarding that request upstream
   would mean really sending it.
2. No credentials are needed, so the sandbox runs with no ambient secrets and a
   syntactically valid fake token is enough.
3. Determinism. Verdicts require agreement across repeated runs, and a live API
   returning varying message IDs, rate-limit headers or timestamps would make
   every run disagree with every other one.

The cost is stated in the README: we observe what the server *tried* to send,
not how a real API would have replied, so behaviour conditional on real response
content is invisible to us.
"""

from __future__ import annotations

import json
from typing import Any

# Fixed so repeated runs produce identical observations.
STUB_MESSAGE_ID = "00000000-0000-4000-8000-000000000000"


def _json(payload: Any, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    body = json.dumps(payload).encode()
    return status, {"Content-Type": "application/json"}, body


def canned_response(host: str, method: str, path: str) -> tuple[int, dict[str, str], bytes]:
    """Return (status, headers, body) for a request the sandbox tried to make.

    Routes are matched on suffix rather than exactly, because the Postmark SDK
    and the raw `fetch` calls in the package build paths slightly differently.
    """
    route = path.split("?", 1)[0].rstrip("/").lower()

    if host.endswith("postmarkapp.com"):
        if route.endswith("/server"):
            # The package calls getServer() during initialisation and exits(1)
            # if it fails, so the server does not start unless this succeeds.
            return _json({"ID": 1, "Name": "mcpgap-sealed", "Color": "blue"})
        if route.endswith("/email/withtemplate") or route.endswith("/email/batchwithtemplates"):
            return _json(
                {
                    "To": "recipient@example.invalid",
                    "SubmittedAt": "2020-01-01T00:00:00Z",
                    "MessageID": STUB_MESSAGE_ID,
                    "ErrorCode": 0,
                    "Message": "OK",
                }
            )
        if route.endswith("/email"):
            return _json(
                {
                    "To": "recipient@example.invalid",
                    "SubmittedAt": "2020-01-01T00:00:00Z",
                    "MessageID": STUB_MESSAGE_ID,
                    "ErrorCode": 0,
                    "Message": "OK",
                }
            )
        if route.endswith("/templates"):
            return _json({"TotalCount": 0, "Templates": []})
        if route.endswith("/stats/outbound"):
            return _json({"Sent": 0, "Bounced": 0, "SMTPApiErrors": 0, "Opens": 0})
        return _json({"ErrorCode": 0, "Message": "OK"})

    # Any other host: a small, well-formed body. This is what a caller-directed
    # attachment fetch receives. Deliberately generic -- we are not pretending
    # to be the real host, only keeping the tool from erroring out so that we
    # can observe what it does with the result.
    return (
        200,
        {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": 'attachment; filename="probe.txt"',
        },
        b"mcpgap sealed-mode placeholder body",
    )
