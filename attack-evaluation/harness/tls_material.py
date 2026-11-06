"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from net import QUESTION_HOST, UPSTREAM_HOST
from safeio import atomic_write, plain_path


def generate(source: Path, root: Path, count: int, unit="no-bypass"):
    """Run via Commands with a cryptography-enabled interpreter; no listener here."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    if not 1 <= count <= 65536:
        raise ValueError("invalid CA pool size")
    spec = importlib.util.spec_from_file_location("nb_make_ca", source / "frontend/make_ca_pool.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pool = root / "ca-pool"
    pool.mkdir(mode=0o700)
    module.main([str(pool), str(count)])  # current production implementation, unmodified
    if len(list(pool.iterdir())) != count:
        raise RuntimeError("CA count mismatch")
    tls = root / "tls"
    tls.mkdir(mode=0o755)
    cert, key = module.make_ca(1)
    ca, ca_key = x509.load_pem_x509_certificate(cert), serialization.load_pem_private_key(key, None)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    names = (UPSTREAM_HOST, QUESTION_HOST)
    if unit == 'credential-binding':
        from cb_profile import NAMES
        names = NAMES
    elif unit != 'no-bypass': raise ValueError('unknown TLS unit')
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, UPSTREAM_HOST)]))
            .issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(hours=20))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(ca_key, hashes.SHA256()))
    for name, data, mode in (("ca.pem", cert, 0o444), ("ca.key", key, 0o600),
                              ("server.pem", leaf.public_bytes(serialization.Encoding.PEM), 0o444),
                              ("server.key", leaf_key.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)):
        atomic_write(tls / name, data)
        (tls / name).chmod(mode)


if __name__ == "__main__":
    if len(sys.argv) not in (4,5) or os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("internal cgroup TLS worker: SOURCE ROOT COUNT")
    generate(plain_path(Path(sys.argv[1])), plain_path(Path(sys.argv[2])), int(sys.argv[3]), sys.argv[4] if len(sys.argv)==5 else "no-bypass")
