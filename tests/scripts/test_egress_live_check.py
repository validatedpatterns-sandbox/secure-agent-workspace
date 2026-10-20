"""Check the live firewall assertion for both cleanup configurations."""

import copy
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "tests/test-egress-firewall.sh").read_text()
VALIDATOR = re.search(
    r"if oc get egressfirewall default[^\n]*\| python3 -c '\n(.*?)\n'; then",
    SCRIPT, re.DOTALL,
).group(1)
BASE_RULES = [
    {"type": "Allow", "to": {"nodeSelector": {"matchLabels": {"kubernetes.io/os": "linux"}}},
     "ports": [{"protocol": "TCP", "port": 443}, {"protocol": "TCP", "port": 80}]},
    {"type": "Allow", "to": {"dnsName": "quay.io"}, "ports": [{"protocol": "TCP", "port": 443}]},
    {"type": "Deny", "to": {"cidrSelector": "0.0.0.0/0"}},
    {"type": "Deny", "to": {"cidrSelector": "::/0"}},
]


def validate(rules):
    return subprocess.run([sys.executable, "-c", VALIDATOR],
                          input=json.dumps({"spec": {"egress": rules}}),
                          text=True, capture_output=True)


def test_no_api_exception_is_valid_when_cleanup_is_disabled():
    assert validate(BASE_RULES).returncode == 0


@pytest.mark.parametrize("cidr,valid", [("192.0.2.10/32", True), ("2001:db8::1/128", True),
                                        ("192.0.2.0/24", False), ("::/0", False)])
def test_api_exception_requires_an_exact_endpoint(cidr, valid):
    rules = copy.deepcopy(BASE_RULES)
    rules.insert(1, {"type": "Allow", "to": {"cidrSelector": cidr},
                     "ports": [{"protocol": "TCP", "port": 6443}]})
    result = validate(rules)
    assert (result.returncode == 0) is valid, result.stderr


def test_wildcards_and_missing_ipv6_deny_are_rejected():
    rules = copy.deepcopy(BASE_RULES)
    rules[1]["to"]["dnsName"] = "*.quay.io"
    assert validate(rules).returncode != 0
    assert validate(BASE_RULES[:-1]).returncode != 0
