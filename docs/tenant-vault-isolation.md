# Per-tenant Vault and ESO secret delivery

## Decision

Each SAW tenant gets a namespace-local External Secrets Operator `SecretStore`
and a distinct Vault Kubernetes-auth role/policy. Vault, rather than only Argo
or Kubernetes RBAC, enforces that one tenant cannot read another tenant's
provider credentials.

The Vault endpoint, CA, mount, auth mount, audience, and path prefix are
platform configuration shared by every tenant. They are not user-specific and
are not generated per user.

```text
platform Vault configuration + one shared Vault CA
                  |
                  v
tenant enrollment in reviewed Git
                  |
                  +--> Vault-provisioning automation: policy + Kubernetes role
                  |
                  +--> Argo/openshell-saw: namespace + ServiceAccount + SecretStore
                  |
                  v
ESO authenticates as that tenant ServiceAccount
                  |
                  v
Vault permits only that tenant's provider path
                  |
                  v
ESO creates tenant-local saw-provider-<name> Kubernetes Secrets
```

## Shared platform configuration

The platform team configures these once:

```yaml
platform:
  issuer: https://identity.example.com/realms/saw
  vault:
    server: https://vault.enterprise.example.com
    mount: secret
    prefix: saw/users
    authMount: kubernetes
    audience: vault
    ca: |-
      -----BEGIN CERTIFICATE-----
      <enterprise Vault CA>
      -----END CERTIFICATE-----
```

The CA is one shared public trust anchor. The tenant chart copies it into a
ConfigMap in each tenant namespace because a namespace-local `SecretStore` must
reference a ConfigMap in its own namespace. It does **not** create a per-user
CA or private certificate.

## Per-user tenant input

Each user/SAW record supplies only identity and credential intent:

```yaml
sawBlueprint:
  platform:
    # Defined once for every tenant.
    issuer: https://identity.example.com/realms/saw
    vault:
      server: https://vault.enterprise.example.com
      mount: secret
      prefix: saw/users
      authMount: kubernetes
      audience: vault
      caBundle: <public Vault CA PEM>
  tenants:
    - name: research
      subject: immutable-oidc-subject
      username: alice
      credentials:
        - name: inference-main
          remoteKey: nvidia
          properties:
            api_key: api_key
```

The tenant key is deterministically derived from the global issuer, `subject`,
and SAW `name`. The display `username` is never used for Vault authorization.

For this example, the expected Vault record is:

```text
secret/data/saw/users/<tenant-key>/providers/nvidia
```

The corresponding namespace-local Kubernetes Secret is:

```text
saw-provider-inference-main
```

Only the declared properties, for example `api_key`, should be materialized in
that Kubernetes Secret. Provider values never appear in Git, Helm values,
ConfigMaps, cloud-init, or guest status/logs.

## Automated provisioning sequence

1. An administrator adds an approved user enrollment to Git.
2. The tenant-provisioning automation computes the tenant key and namespace.
3. That automation creates or updates a Vault policy restricted to exactly:

   ```text
   <vault-prefix>/<tenant-key>/providers/*
   ```

4. It creates a Vault Kubernetes-auth role bound to exactly:
   - ServiceAccount: `saw-vault-reader`;
   - namespace: the derived tenant namespace;
   - audience: the platform Vault audience;
   - policy: that tenant's policy only.
5. Argo ApplicationSet renders one `openshell-saw` Application for the tenant.
6. The chart creates the tenant namespace, `saw-vault-reader` ServiceAccount,
   tenant-local CA ConfigMap, `SecretStore`, and one `ExternalSecret` per
   declared credential.
7. ESO requests a ServiceAccount token with the configured audience, logs into
   Vault using the tenant's role, reads only the permitted provider record, and
   writes the tenant-local `saw-provider-<credential-name>` Secret.
8. The VM mounts only listed provider Secrets read-only through virtiofs. The
   VM has no Kubernetes API token and cannot list or fetch other Secrets.

## What is automated today

The chart/ApplicationSet can automate steps 5–8 once the tenant record exists.
It creates the ESO resources and names the required Vault role/path
deterministically.

The chart must **not** receive a Vault administrator token, so it cannot safely
perform steps 3–4 itself. Those are performed by separate platform-owned Vault
automation, such as Terraform, a controlled CI job, or an approved Vault
operator workflow. That automation consumes the same reviewed enrollment input
and must run before or alongside the Argo tenant sync.

## Required safeguards

- The Vault provisioning identity may create tenant policies/roles but must not
  grant wildcard access outside the SAW provider prefix.
- Only platform automation may create or modify `ExternalSecret`, `SecretStore`,
  and `saw-vault-reader` resources in a tenant namespace.
- Enforce Git review for enrollment identity and credential-path changes.
- Audit Vault login/read events, ESO reconciliation failures, and Argo changes.
- Test two tenants: Alice's ServiceAccount must be denied Bob's provider path,
  and vice versa.

## Failure behavior

If the Vault role/policy does not exist or does not match the namespace,
ServiceAccount, audience, or derived path, ESO must fail closed: no provider
Secret is created or refreshed. Argo reconciliation success alone does not mean
the workspace has provider credentials or is ready.
