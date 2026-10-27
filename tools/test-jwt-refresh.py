#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["fastmcp==4.1.3", "mcp==2.3.0", "PyJWT==2.15.1", "cryptography==50.0.2"]
# ///
"""Exercise strict JWT rejection and real MCP OAuth refresh on loopback only."""
import argparse
import asyncio
import base64
import http.server
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastmcp.client.auth import PrivateKeyJWTOAuthProvider, SignedJWTParameters
from fastmcp import Client
import jwt
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def number(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


async def exercise(binary):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    calls = []
    refreshes = []
    authorizations = []
    authorization_parameters = {}
    machine_grants = []
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = f"http://127.0.0.1:{port()}"
    url = f"http://127.0.0.1:{port()}/all/mcp"

    def token(**updates):
        now = int(time.time())
        claims = {"iss": issuer, "sub": "synthetic-person", "aud": url,
                  "iat": now - 1, "exp": now + 5, "scope": "all:use"}
        claims.update(updates)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test", "typ": "at+jwt"})

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value=None):
            body = json.dumps(value).encode() if value is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/jwks":
                return self.reply(200, {"keys": [{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
                                                  "n": number(public.n), "e": number(public.e)}]})
            if self.path.startswith("/.well-known/"):
                return self.reply(200, {"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                    "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
                    "response_types_supported": ["code"], "grant_types_supported": ["refresh_token", "authorization_code", "client_credentials"],
                    "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"], "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["all:use"]})
            self.reply(405)

        def do_DELETE(self):
            self.reply(204)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/token":
                form = urllib.parse.parse_qs(body.decode())
                grant = form.get("grant_type")
                ttl = 5
                if grant == ["refresh_token"]:
                    assert form.get("refresh_token") == ["synthetic-refresh"]
                    refreshes.append(time.time())
                elif grant == ["authorization_code"]:
                    assert form.get("code") == ["synthetic-code"]
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(form['code_verifier'][0].encode()).digest()).rstrip(b'=').decode()
                    assert authorization_parameters['code_challenge'] == [challenge]
                elif grant == ["client_credentials"]:
                    jwt.decode(form['client_assertion'][0], client_key.public_key(), algorithms=['RS256'],
                               audience=issuer, issuer='synthetic-machine', subject='synthetic-machine')
                    machine_grants.append(time.time())
                    ttl = 3600  # Exercise reactive renewal when a cached token expires early.
                else:
                    raise AssertionError('Unexpected synthetic grant')
                result = {"access_token": token(), "token_type": "Bearer", "expires_in": ttl, "scope": "all:use"}
                if grant != ["client_credentials"]: result['refresh_token'] = 'synthetic-refresh'
                return self.reply(200, result)
            message = json.loads(body)
            if "id" not in message:
                return self.reply(202)
            method = message["method"]
            if method == "initialize":
                result = {"protocolVersion": message["params"]["protocolVersion"], "capabilities": {"tools": {}},
                          "serverInfo": {"name": "synthetic", "version": "1"}}
            elif method == "tools/list":
                result = {"tools": [{"name": "echo", "description": "Read-only synthetic canary",
                          "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}}]}
            elif method == "tools/call":
                calls.append(message["id"])
                result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
            elif method == "ping":
                result = {}
            else:
                return self.reply(200, {"jsonrpc": "2.0", "id": message["id"],
                                       "error": {"code": -32601, "message": "Unknown method"}})
            self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": result})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", int(urllib.parse.urlsplit(issuer).port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    gateway_port = urllib.parse.urlsplit(url).port
    config = {"config": {"adminAddr": f"127.0.0.1:{port()}", "statsAddr": f"127.0.0.1:{port()}",
                         "readinessAddr": f"127.0.0.1:{port()}"},
        "gateways": {"default": {"port": gateway_port, "bindAddress": "127.0.0.1"}},
        "routes": [{"name": "synthetic", "matches": [{"path": {"exact": p}} for p in
            ["/all/mcp", "/.well-known/oauth-protected-resource/all/mcp"]],
            "policies": {"mcpAuthentication": {"mode": "strict", "issuer": issuer, "audiences": [url],
                "jwks": {"url": issuer + "/jwks"}, "jwtValidationOptions": {"requiredClaims": ["exp", "sub"],
                    "strictTimestamps": True, "maxTokenLifetime": "15m"},
                "resourceMetadata": {"resource": url, "scopesSupported": ["all:use"]}},
                "authorization": {"rules": ["has(jwt.scope) && jwt.scope == 'all:use'"]}},
            "backends": [{"mcp": {"targets": [{"name": "fixture", "mcp": {"host": issuer + "/backend/mcp"}}],
                "prefixMode": "never", "statefulMode": "stateless"}}]}]}
    with tempfile.TemporaryDirectory(prefix="jwt-refresh-") as directory:
        root = Path(directory)
        path = root / "config.json"
        path.write_text(json.dumps(config))
        with (root / "gateway.log").open("w+") as log:
            proc = subprocess.Popen([str(binary), "--file", str(path)], cwd=root,
                                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, stdout=log, stderr=log)
            try:
                for _ in range(200):
                    if proc.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read()[-2000:])
                    try:
                        with socket.create_connection(("127.0.0.1", gateway_port), timeout=.1):
                            break
                    except OSError:
                        await asyncio.sleep(.1)
                else:
                    raise RuntimeError("Gateway did not start")

                results = []
                now = int(time.time())
                for label, updates, expected in [
                    ("expired", {"iat": now - 100, "exp": now - 10}, 401),
                    ("expiry_current_second", {"exp": now}, 401),
                    ("expired_fractional_timestamp", {"iat": now - 100, "exp": now - .5}, 401),
                    ("valid_fractional_timestamps", {"iat": now - .5, "nbf": now - .25, "exp": now + 300.5}, 200),
                    ("future_iat", {"iat": now + 1}, 401),
                    ("future_nbf", {"nbf": now + 1}, 401),
                    ("excessive_lifetime", {"exp": now + 901}, 401),
                    ("malformed_timestamp", {"iat": "yesterday"}, 401),
                    ("wrong_audience", {"aud": "https://other.example/mcp"}, 401),
                    ("wrong_scope", {"scope": "different:use"}, 403),
                ]:
                    request = urllib.request.Request(url, data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                        headers={"Authorization": "Bearer " + token(**updates), "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
                    try:
                        response = urllib.request.urlopen(request, timeout=10)
                    except urllib.error.HTTPError as error:
                        response = error
                    assert response.status == expected, (label, response.status)
                    challenge = response.headers.get("WWW-Authenticate", "")
                    if expected == 401:
                        assert 'error="invalid_token"' in challenge and "resource_metadata=" in challenge, label
                    response.close()
                    results.append({"case": label, "status": expected})
                assert not calls, "Rejected calls reached the backend"

                metadata = OAuthClientMetadata(redirect_uris=["http://127.0.0.1/callback"],
                    token_endpoint_auth_method="none", scope="all:use")
                class Storage:
                    tokens = None
                    client = OAuthClientInformationFull(client_id="synthetic", issuer=issuer, **metadata.model_dump())
                    async def get_tokens(self): return self.tokens
                    async def set_tokens(self, value): self.tokens = value
                    async def get_client_info(self): return self.client
                    async def set_client_info(self, value): self.client = value

                async def authorize_fixture(authorization_url):
                    authorizations.append(time.time())
                    authorization_parameters.update(urllib.parse.parse_qs(urllib.parse.urlsplit(authorization_url).query))
                async def fixture_callback():
                    return AuthorizationCodeResult(code='synthetic-code', state=authorization_parameters['state'][0], iss=issuer)
                storage = Storage()
                auth = OAuthClientProvider(server_url=url, client_metadata=metadata, storage=storage,
                                           redirect_handler=authorize_fixture, callback_handler=fixture_callback)
                async with Client(url, auth=auth, timeout=20) as client:
                    assert not (await client.call_tool("echo", {})).is_error
                    assert len(calls) == 1 and not refreshes
                    # Use the real authorization-code exchange and expiry accounting.
                    await asyncio.sleep(5.2)
                    assert not (await client.call_tool("echo", {})).is_error
                    assert len(calls) == 2 and len(refreshes) == 1
                    await asyncio.sleep(5.2)
                    responses = await asyncio.gather(*(client.call_tool("echo", {}) for _ in range(4)))
                    assert all(not r.is_error for r in responses)
                    assert len(calls) == 6, "Refresh duplicated a backend tool call"
                    assert 2 <= len(refreshes) <= 5
                assert len(authorizations) == 1, "Expiry unexpectedly required another authorization"
                results.append({"case": "user_oauth_refresh_and_concurrent_calls", "backend_calls": len(calls),
                                "refreshes": len(refreshes), "additional_authorizations": 0})
                pem = client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()).decode()
                parameters = SignedJWTParameters(issuer='synthetic-machine', subject='synthetic-machine', signing_key=pem)
                machine_auth = PrivateKeyJWTOAuthProvider(mcp_url=url, client_id='synthetic-machine',
                    issuer=issuer, scopes=['all:use'], assertion_provider=parameters.create_assertion_provider())
                async with Client(url, auth=machine_auth, timeout=20) as client:
                    assert not (await client.call_tool('echo', {})).is_error
                    assert len(machine_grants) == 1
                    await asyncio.sleep(5.2)
                    assert not (await client.call_tool('echo', {})).is_error
                    assert len(machine_grants) == 2 and len(calls) == 8
                results.append({'case': 'workload_reactive_401_recovery', 'grants': len(machine_grants),
                                'backend_calls': 2, 'interactive_login': False})
                return results
            except BaseException:
                log.seek(0)
                print(log.read()[-3000:])
                raise
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(exercise(args.binary.resolve())), indent=2))
