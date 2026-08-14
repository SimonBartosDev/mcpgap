"""Ephemeral certificate authority for the sealed proxy.

A fresh CA is generated per run and lives only in the run's working directory.
Nothing is ever installed into a system or user trust store: the CA is handed to
the child process through NODE_EXTRA_CA_CERTS and is trusted by that process
alone. A scanner that permanently trusted its own MITM CA machine-wide would be
a worse vulnerability than anything it detects.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Certificate validity is anchored to a fixed instant rather than "now" so that
# two runs of the same scan produce byte-comparable certificates. Run-to-run
# variation is the enemy of the N-runs agreement rule.
_NOT_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
_NOT_AFTER = dt.datetime(2040, 1, 1, tzinfo=dt.UTC)


class EphemeralCA:
    """Mints short-lived leaf certificates for whatever host is requested."""

    def __init__(self, workdir: Path) -> None:
        self._workdir = workdir
        self._leaves: dict[str, tuple[bytes, bytes]] = {}
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "mcpgap ephemeral CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mcpgap"),
            ]
        )
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOT_BEFORE)
            .not_valid_after(_NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def write_ca_bundle(self) -> Path:
        """Write the CA certificate for the child process to trust."""
        path = self._workdir / "mcpgap-ca.pem"
        path.write_bytes(self.cert_pem)
        return path

    def leaf_for(self, hostname: str) -> tuple[Path, Path]:
        """Return (cert_path, key_path) for `hostname`, minting on first use."""
        if hostname not in self._leaves:
            self._leaves[hostname] = self._mint(hostname)
        cert_pem, key_pem = self._leaves[hostname]
        safe = hostname.replace(":", "_").replace("/", "_").replace("*", "_")
        cert_path = self._workdir / f"leaf-{safe}.pem"
        key_path = self._workdir / f"leaf-{safe}.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        return cert_path, key_path

    def _mint(self, hostname: str) -> tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOT_BEFORE)
            .not_valid_after(_NOT_AFTER)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert.public_bytes(serialization.Encoding.PEM), key_pem
