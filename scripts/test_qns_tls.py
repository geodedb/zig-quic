#!/usr/bin/env python3
"""Check real image credentials under the endpoint's unprivileged identity."""

import io
import os
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path


class ContainerCredentialTests(unittest.TestCase):
    image = "zig-qns:local"

    def docker(self, *args):
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=30, check=False
        )

    def container(self, *args):
        name = "qns-tls-test-" + uuid.uuid4().hex
        try:
            return self.docker(
                "run",
                "--rm",
                "--name",
                name,
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SETGID",
                *args,
            )
        finally:
            self.docker("rm", "-f", name)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="qns-tls-fixture-")
        self.addCleanup(temporary.cleanup)
        self.fixture = Path(temporary.name)
        subprocess.run(
            [
                "bash",
                str(Path(__file__).with_name("generate_interop_certs.sh")),
                str(self.fixture),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        self.volume = "qns-tls-test-" + uuid.uuid4().hex
        created = self.docker("volume", "create", self.volume)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.addCleanup(self.docker, "volume", "rm", self.volume)

    def install(self, *, missing_key=False, mismatched_key=False):
        command = "umask 077; chmod 700 /certs; chmod 600 /certs/cert.pem; "
        if mismatched_key:
            command += "openssl ecparam -genkey -name prime256v1 -out /certs/priv.key; "
        elif not missing_key:
            command += "chmod 600 /certs/priv.key; "
        command += "stat -c '%U:%G %a' /certs/cert.pem"
        name = "qns-tls-fixture-" + uuid.uuid4().hex
        try:
            created = self.docker(
                "create",
                "--name",
                name,
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--entrypoint",
                "bash",
                "-v",
                f"{self.volume}:/certs",
                self.image,
                "-euc",
                command,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            # Send through the Docker API: the CI client's /tmp is not a bind
            # mount on the separate Docker-in-Docker daemon filesystem. Set
            # archive ownership explicitly: copying host files can preserve
            # their host UID, which would not exercise a root-private mount.
            files = [("cert.pem", "cert.pem")]
            if not missing_key and not mismatched_key:
                files.append(("key.pem", "priv.key"))
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as bundle:
                for source, target in files:
                    data = (self.fixture / source).read_bytes()
                    entry = tarfile.TarInfo(target)
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = "root"
                    entry.mode = 0o600
                    entry.size = len(data)
                    bundle.addfile(entry, io.BytesIO(data))
            copied = subprocess.run(
                ["docker", "cp", "--archive", "-", f"{name}:/certs/"],
                input=archive.getvalue(),
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(copied.returncode, 0, copied.stderr.decode())
            result = self.docker("start", "-a", name)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("root:root 600", result.stdout)
        finally:
            self.docker("rm", "-f", name)

    def check(self, mounted=False):
        mounts = ["-v", f"{self.volume}:/certs:ro"] if mounted else []
        return self.container(*mounts, "-e", "INTEROP_TLS_CHECK=1", self.image)

    def test_fallback_key_is_private_and_readable_as_quic(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("quic:quic 600", result.stdout)
        self.assertIn("CA:FALSE", result.stdout)

    def test_root_private_mount_is_staged_without_changing_identity_or_permissions(
        self,
    ):
        self.install()
        result = self.check(mounted=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("quic:quic 600", result.stdout)
        fingerprint = (
            subprocess.check_output(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(self.fixture / "cert.pem"),
                    "-noout",
                    "-fingerprint",
                    "-sha256",
                ],
                text=True,
            )
            .strip()
            .split("=", 1)[1]
        )
        self.assertIn(fingerprint, result.stdout)
        source = self.container(
            "--entrypoint",
            "stat",
            "-v",
            f"{self.volume}:/certs:ro",
            self.image,
            "-c",
            "%U:%G %a",
            "/certs/priv.key",
        )
        self.assertEqual(source.returncode, 0, source.stderr)
        self.assertEqual(source.stdout.strip(), "root:root 600")

    def test_partial_mount_fails_instead_of_generating_a_different_identity(self):
        self.install(missing_key=True)
        self.assertNotEqual(self.check(mounted=True).returncode, 0)

    def test_mismatched_mounted_key_fails_before_endpoint_start(self):
        self.install(mismatched_key=True)
        self.assertNotEqual(self.check(mounted=True).returncode, 0)


if __name__ == "__main__":
    # Host FIPS fixture paths are not available inside the image.
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "LD_LIBRARY_PATH"):
        os.environ.pop(name, None)
    unittest.main(verbosity=2)
