#!/usr/bin/env python3
"""Minimal AWS IMDS mock for local demos (bind 169.254.169.254 on lo first)."""

from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE = "TempestDemoRole"
CREDS = """{
  "Code": "Success",
  "LastUpdated": "2026-08-04T02:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIATEMPST00000000001",
  "SecretAccessKey": "wJalrXUtnFEMI/DEMO+KEY+NOT+REAL+abcdef1234567890",
  "Token": "IQoJb3JpZ2luX2VjEKn//////////wEaCXVzLWVhc3QtMSJHMEUCIDTempestDemoSessionTokenNotRealAnymore1234567890abcdef",
  "Expiration": "2026-08-04T08:00:00Z"
}"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[mock-imds] {self.address_string()} - {fmt % args}")

    def do_PUT(self):
        if self.path == "/latest/api/token":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"mock-imds-token-demo")
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == "/latest/meta-data/iam/security-credentials/":
            body = f"{ROLE}\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == f"/latest/meta-data/iam/security-credentials/{ROLE}":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(CREDS.encode())
        else:
            self.send_error(404)


if __name__ == "__main__":
    host = "169.254.169.254"
    port = 80
    print(f"mock IMDS listening on http://{host}:{port}/")
    HTTPServer((host, port), Handler).serve_forever()
