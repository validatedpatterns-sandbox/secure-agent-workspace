"""The controller and enrollment read one owner-bound public CA ConfigMap."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from saw_kubernetes.gateway_ca import OWNER, configmap_path, read_public_ca


NAMESPACE = "saw-alice"
GATEWAY = "alice"
OWNER_ID = "802fe583-9329-54b6-b5b4-7be58ec171f3"


@pytest.fixture(scope="module")
def certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Public test CA")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    value = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=1))
             .not_valid_after(now + timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .sign(key, hashes.SHA256()))
    return value.public_bytes(serialization.Encoding.PEM).decode("ascii")


def configmap(certificate):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": GATEWAY + "-gateway-ca", "namespace": NAMESPACE,
                     "labels": {OWNER: OWNER_ID}},
        "data": {"ca.crt": certificate},
    }


def test_reads_one_valid_owner_bound_public_ca(certificate):
    reads = []
    result = read_public_ca(NAMESPACE, GATEWAY, OWNER_ID,
                            lambda path: reads.append(path) or configmap(certificate))
    assert result == certificate
    assert reads == [configmap_path(NAMESPACE, GATEWAY)]


@pytest.mark.parametrize("change", [
    lambda obj: obj["metadata"].update(name="other-gateway-ca"),
    lambda obj: obj["metadata"].update(namespace="saw-other"),
    lambda obj: obj["metadata"]["labels"].update({OWNER: "foreign"}),
    lambda obj: obj.update(immutable=False),
    lambda obj: obj["metadata"].update(deletionTimestamp="2026-01-01T00:00:00Z"),
    lambda obj: obj["metadata"].update(ownerReferences=[{"name": "foreign"}]),
    lambda obj: obj["data"].update(extra="not public CA material"),
    lambda obj: obj["data"].update({"ca.crt": "not a certificate"}),
])
def test_rejects_changed_or_foreign_public_ca(certificate, change):
    obj = configmap(certificate)
    change(obj)
    with pytest.raises(ValueError, match="public gateway CA is missing, foreign or malformed"):
        read_public_ca(NAMESPACE, GATEWAY, OWNER_ID, lambda _: obj)


@pytest.mark.parametrize("namespace,gateway", [("../other", GATEWAY), (NAMESPACE, "../other")])
def test_rejects_path_components_before_api_read(namespace, gateway):
    reads = []
    with pytest.raises(ValueError, match="public gateway CA"):
        read_public_ca(namespace, gateway, OWNER_ID, lambda path: reads.append(path))
    assert reads == []
