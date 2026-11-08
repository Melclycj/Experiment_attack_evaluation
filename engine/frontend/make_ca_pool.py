"""Fill a deployment's CA pool (validation.md S-16; agent-rm-model 6.3 TLS 行): one directory per future execution, each
holding a fresh self-signed CA (ca.pem, ca.key). The spawner moves one entry into each execution's row directory and
the child mounts it read-only at /w2/ca; the frontend signs leaf certificates with it, the agent trusts it, and no other
trust store ever gets it (D-08). Run offline by the deployment's owner; not in the TCB.

    python3 make_ca_pool.py <pool directory> <count> [--days 30]

Needs the `cryptography` package (the frontend venv has it). Equivalent openssl invocation, for a deployment without it:
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=w2 execution CA" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca.key -out ca.pem
"""
from __future__ import annotations

import argparse
import datetime
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_ca(days: int) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'w2 execution CA {secrets.token_hex(4)}')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument('pool', type=Path)
    p.add_argument('count', type=int)
    p.add_argument('--days', type=int, default=30)
    args = p.parse_args(argv)
    args.pool.mkdir(mode=0o700, parents=True, exist_ok=True)
    for _ in range(args.count):
        cert, key = make_ca(args.days)
        entry = args.pool / secrets.token_hex(8)
        entry.mkdir(mode=0o755)
        for name, data in (('ca.pem', cert), ('ca.key', key)):
            fd = os.open(entry / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)   # readable in the cell by design
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
    print(f'{args.count} CA entries in {args.pool}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
