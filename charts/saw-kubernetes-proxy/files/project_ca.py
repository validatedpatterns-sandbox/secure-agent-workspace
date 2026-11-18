"""Project only the stock proxy's public CA; refuse replacement or adoption.

The preceding init container runs the unchanged SAW proxy init-ca command.
This helper never reads a Secret, returns credential data or rotates trust.
"""
import json
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, build_opener
import uuid

OWNER = "saw.redhat.com/runtime-owner"
KEEP = "Prune=false,Delete=false"
NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
LIMIT = 128 * 1024


class Failure(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self):
        root = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        self.token = root / 'token'
        self.opener = build_opener(NoRedirect(), HTTPSHandler(
            context=ssl.create_default_context(cafile=str(root / 'ca.crt'))))

    def call(self, method, path, body=None):
        try:
            token = self.token.read_text().strip()
            if not token or any(c.isspace() for c in token):
                raise ValueError()
            data = None if body is None else json.dumps(body).encode()
            request = Request('https://kubernetes.default.svc' + path, data=data,
                              headers={'Authorization': 'Bearer ' + token,
                                       'Content-Type': 'application/json'}, method=method)
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError()
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except HTTPError as exc:
            status = exc.code
            exc.close()
            if (method == 'GET' and status == 404) or (method == 'POST' and status == 409):
                return None
            raise Failure(f'projection API failed ({status})') from None
        except (OSError, ValueError, URLError):
            raise Failure('projection API unavailable') from None


def validate(config):
    if not isinstance(config, dict) or set(config) != {'ownerID', 'namespace', 'targetNamespace', 'name'}:
        raise Failure('invalid projection fields')
    for key in ('namespace', 'targetNamespace', 'name'):
        name = config[key]
        if (not isinstance(name, str) or len(name) > 63 or not NAME.fullmatch(name)
                or name == 'default' or name.startswith(('openshift', 'kube-'))):
            raise Failure('dedicated projection names required')
    if config['namespace'] == config['targetNamespace']:
        raise Failure('proxy and runtime namespaces must differ')
    try:
        identity = uuid.UUID(config['ownerID'])
        if str(identity) != config['ownerID'] or identity.int == 0:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Failure('canonical nonzero installation UUID required') from None


def mapping(value):
    if not isinstance(value, dict):
        raise Failure('invalid projection object')
    return value


def metadata(obj):
    meta = mapping(mapping(obj or {}).get('metadata', {}))
    mapping(meta.get('labels', {}))
    mapping(meta.get('annotations', {}))
    return meta


def project(api, config):
    validate(config)
    owner = config['ownerID']
    for namespace in (config['namespace'], config['targetNamespace']):
        obj = api.call('GET', '/api/v1/namespaces/' + namespace)
        meta = metadata(obj)
        if (meta.get('name') != namespace or meta.get('deletionTimestamp')
                or meta.get('labels', {}).get(OWNER) != owner):
            raise Failure('namespace ownership mismatch')
    name = config['name']
    source = api.call('GET', f"/api/v1/namespaces/{config['namespace']}/configmaps/{name}")
    meta = metadata(source)
    data = mapping((source or {}).get('data', {}))
    if (meta.get('name') != name or meta.get('namespace') != config['namespace']
            or meta.get('deletionTimestamp') or set(data) != {'ca.crt'}
            or (source or {}).get('binaryData')):
        raise Failure('invalid public CA source')
    cert = data['ca.crt']
    if (not isinstance(cert, str) or len(cert) > 32768 or 'PRIVATE KEY' in cert
            or not re.fullmatch(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', cert)):
        raise Failure('public certificate only')
    try:
        ssl.create_default_context().load_verify_locations(cadata=cert)
    except (ValueError, ssl.SSLError):
        raise Failure('invalid public certificate') from None
    base = f"/api/v1/namespaces/{config['targetNamespace']}/configmaps"
    existing = api.call('GET', base + '/' + name)
    if existing is None:
        api.call('POST', base, {'apiVersion': 'v1', 'kind': 'ConfigMap',
                 'metadata': {'name': name, 'namespace': config['targetNamespace'],
                              'labels': {OWNER: owner},
                              'annotations': {'argocd.argoproj.io/sync-options': KEEP}},
                 'immutable': True, 'data': {'ca.crt': cert}})
        existing = api.call('GET', base + '/' + name)
    meta = metadata(existing)
    if (meta.get('name') != name or meta.get('namespace') != config['targetNamespace']
            or meta.get('deletionTimestamp') or meta.get('ownerReferences')
            or meta.get('labels', {}).get(OWNER) != owner
            or meta.get('annotations', {}).get('argocd.argoproj.io/sync-options') != KEEP
            or (existing or {}).get('immutable') is not True
            or (existing or {}).get('binaryData') or (existing or {}).get('data') != {'ca.crt': cert}):
        raise Failure('public projection differs; explicit trust recovery required')


if __name__ == '__main__':
    try:
        project(Api(), json.loads(Path('/config/config.json').read_text()))
        print('Public proxy CA projection verified')
    except (Failure, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Failure) else 'projection configuration unavailable', file=sys.stderr)
        sys.exit(1)
