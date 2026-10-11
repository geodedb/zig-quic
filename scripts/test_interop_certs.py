#!/usr/bin/env python3
"""Exercise the real certificate generator and its failure cleanup."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("generate_interop_certs.sh")


class InteropCertificateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="interop-certs-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / "certificate bundle"

    def generate(self, path, env=None):
        return subprocess.run(
            ["bash", str(SCRIPT), str(path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def openssl(self, *args):
        return subprocess.run(
            ["openssl", *map(str, args)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def verify(self, ca, host="localhost"):
        return self.openssl(
            "verify",
            "-CAfile",
            ca,
            "-purpose",
            "sslserver",
            "-verify_hostname",
            host,
            self.bundle / "cert.pem",
        )

    def test_leaf_is_distinct_and_verifies_only_for_its_ca_and_hostname(self):
        result = self.generate(self.bundle)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.verify(self.bundle / "ca.pem").returncode, 0)
        self.assertNotEqual(
            self.verify(self.bundle / "ca.pem", "wrong.invalid").returncode, 0
        )
        text = self.openssl("x509", "-in", self.bundle / "cert.pem", "-noout", "-text")
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("CA:FALSE", text.stdout)
        self.assertNotEqual(
            (self.bundle / "cert.pem").read_bytes(),
            (self.bundle / "ca.pem").read_bytes(),
        )
        unrelated = self.root / "unrelated"
        self.assertEqual(self.generate(unrelated).returncode, 0)
        self.assertNotEqual(self.verify(unrelated / "ca.pem").returncode, 0)

    def test_matching_server_key_is_private_and_ca_signing_key_is_removed(self):
        result = self.generate(self.bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {p.name for p in self.bundle.iterdir()}, {"ca.pem", "cert.pem", "key.pem"}
        )
        self.assertEqual(stat.S_IMODE((self.bundle / "key.pem").stat().st_mode), 0o600)
        certificate = self.openssl(
            "x509", "-in", self.bundle / "cert.pem", "-pubkey", "-noout"
        )
        key = self.openssl("pkey", "-in", self.bundle / "key.pem", "-pubout")
        self.assertEqual(certificate.returncode, 0, certificate.stderr)
        self.assertEqual(key.returncode, 0, key.stderr)
        self.assertEqual(certificate.stdout, key.stdout)

    def test_openssl_failure_propagates_without_publishing_partial_material(self):
        commands = self.root / "commands"
        commands.mkdir()
        failure = commands / "openssl"
        failure.write_text("#!/bin/sh\nexit 73\n")
        failure.chmod(0o755)
        env = {**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"]}
        result = self.generate(self.bundle, env)
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertEqual(list(self.bundle.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
