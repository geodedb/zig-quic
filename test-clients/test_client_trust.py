#!/usr/bin/env python3
"""Real QUIC exchanges exercise each client's trust and success contract.

Run once per implementation with QUIC_TRUST_CLIENT=aioquic, go, or quinn.
QUIC_TRUST_BINARY may select the already-built Go or Quinn client executable.
"""

import asyncio
import datetime
import ipaddress
import os
import sys
import tempfile
import unittest
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
CLIENT = os.environ.get("QUIC_TRUST_CLIENT", "aioquic")


def certificates(wrong_host=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client trust fixture")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    names = (
        [x509.DNSName("other.invalid")]
        if wrong_host
        else [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture server")])
        )
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca.public_bytes(serialization.Encoding.PEM), leaf, leaf_key


class FixtureServer(QuicConnectionProtocol):
    def __init__(self, *args, response, unsolicited, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = response
        self.unsolicited = unsolicited
        self.requests = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            request = self.requests.setdefault(event.stream_id, bytearray())
            request.extend(event.data)
            if len(request) > 4096:
                self.close(error_code=1, reason_phrase="oversized fixture request")
            elif event.end_stream:
                if request != b"GET /\r\n":
                    self.close(error_code=1, reason_phrase="unexpected fixture request")
                    return
                if self.unsolicited:
                    self._quic.send_stream_data(
                        self._quic.get_next_available_stream_id(is_unidirectional=True),
                        b"unsolicited-data",
                        end_stream=True,
                    )
                self._quic.send_stream_data(
                    event.stream_id, self.response, end_stream=True
                )
                self.transmit()


class ClientTrustTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(
        self,
        *,
        trust="trusted",
        wrong_host=False,
        response=b"fixture-response",
        unsolicited=False,
    ):
        with tempfile.TemporaryDirectory(prefix="quic-client-trust-") as temporary:
            root = Path(temporary)
            ca, certificate, private_key = certificates(wrong_host)
            config = QuicConfiguration(is_client=False, alpn_protocols=["hq-interop"])
            config.certificate = certificate
            config.private_key = private_key
            server = await serve(
                "127.0.0.1",
                0,
                configuration=config,
                create_protocol=lambda *args, **kwargs: FixtureServer(
                    *args, response=response, unsolicited=unsolicited, **kwargs
                ),
            )
            try:
                port = server._transport.get_extra_info("sockname")[1]
                if CLIENT == "aioquic":
                    command = [
                        sys.executable,
                        str(ROOT / "aioquic-client/test_client.py"),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                    ]
                elif CLIENT == "go":
                    binary = os.environ.get(
                        "QUIC_TRUST_BINARY",
                        str(ROOT / "quic-go-client/quic-go-test-client"),
                    )
                    command = [binary, "--addr", f"127.0.0.1:{port}"]
                elif CLIENT == "quinn":
                    binary = os.environ.get(
                        "QUIC_TRUST_BINARY",
                        str(ROOT / "quinn-client/target/release/quinn-test-client"),
                    )
                    command = [
                        binary,
                        "--addr",
                        f"127.0.0.1:{port}",
                        "--server-name",
                        "localhost",
                    ]
                else:
                    self.fail(f"Unknown implementation: {CLIENT}")
                if trust != "default":
                    if trust == "unrelated":
                        ca = certificates()[0]
                    elif trust == "invalid":
                        ca = b"not a certificate"
                    ca_path = root / "ca.pem"
                    ca_path.write_bytes(ca)
                    command += ["--ca-file", str(ca_path)]
                child = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "SSLKEYLOGFILE": "", "NO_COLOR": "1"},
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        child.communicate(), timeout=8
                    )
                except BaseException:
                    if child.returncode is None:
                        child.kill()
                    await child.wait()
                    raise
                output = (stdout + stderr).decode(errors="replace")
                for invalid_option in [
                    "unrecognized arguments",
                    "unexpected argument",
                    "flag provided but not defined",
                ]:
                    self.assertNotIn(
                        invalid_option,
                        output,
                        "Client rejected the trust option instead of exercising TLS",
                    )
                return child.returncode, output
            finally:
                server.close()
                await asyncio.sleep(0)

    async def test_explicit_ca_accepts_verified_exchange(self):
        code, output = await self.exchange()
        self.assertEqual(code, 0, output)
        self.assertIn("fixture-response", output)
        self.assertIn("Test completed successfully", output)

    async def assert_rejected(self, **kwargs):
        code, output = await self.exchange(**kwargs)
        self.assertNotEqual(code, 0, output)
        self.assertNotIn("Test completed successfully", output)
        return output

    async def test_secure_default_rejects_unknown_ca(self):
        output = await self.assert_rejected(trust="default")
        self.assertIn("cert", output.lower())

    async def test_unrelated_ca_is_rejected(self):
        output = await self.assert_rejected(trust="unrelated")
        self.assertIn("cert", output.lower())

    async def test_trusted_ca_does_not_disable_hostname_verification(self):
        output = await self.assert_rejected(wrong_host=True)
        self.assertRegex(output.lower(), "cert|hostname")

    async def test_invalid_ca_is_rejected(self):
        await self.assert_rejected(trust="invalid")

    async def test_empty_response_is_rejected(self):
        output = await self.assert_rejected(response=b"")
        self.assertIn("empty response", output.lower())

    async def test_unrelated_stream_cannot_satisfy_the_request(self):
        output = await self.assert_rejected(response=b"", unsolicited=True)
        self.assertIn("empty response", output.lower())


if __name__ == "__main__":
    unittest.main()
