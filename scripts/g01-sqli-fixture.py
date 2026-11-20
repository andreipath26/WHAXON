from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlmap_boolean_oracle import sqlmap_boolean_oracle


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        value = query.get("id", [""])[0].lower()
        if path == "/health":
            status, body = 200, b"ok"
        elif path in {"/admin", "/robots.txt"}:
            status, body = 200, b"fixture"
        elif path == "/search":
            # Deterministic boolean oracle for the fixed SQLmap smoke. A quote
            # probe emits a parser marker; boolean conditions vary only a
            # constant response and never access or mutate a database.
            if value.strip() == "'":
                status, body = 200, b"SQLite error: near \"'\": syntax error\\n"
            else:
                status, body = 200, sqlmap_boolean_oracle(value)
        else:
            status, body = 404, b"not found"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
