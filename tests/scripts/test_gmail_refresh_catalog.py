"""Refresh material stays secret in forms and never becomes VM metadata."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def generator():
    spec = importlib.util.spec_from_file_location('catalog_refresh', ROOT / 'scripts/saw-profile-catalog.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gmail_fields_are_secret_refresh_material():
    cat = generator().catalog()['profiles']['personal-assistant']
    assert cat['harnessRequired'] is True
    gmail = cat['secrets']['gmail']
    assert gmail['refresh'] == {'strategy':'oauth2_refresh_token','credentialKey':'access_token'}
    assert {f['key'] for f in gmail['fields']} == {'client_id','client_secret','refresh_token'}
    assert all(f['kind']=='secret' and f['refreshMaterial'] and f['required'] for f in gmail['fields'])
    assert 'refresh' not in cat['secrets']['slack']


def test_strategy_mismatch_is_rejected():
    with pytest.raises(ValueError,match='does not match'):
        generator().secret_fields({'type':'gmail','credentialSecretKey':'access_token','refresh':{'strategy':'oauth2-refresh-token'}})
