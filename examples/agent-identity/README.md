# Agent identity examples

These files contain no credentials or values from a particular cluster. Set
the trust domain, issuer, and test identity from the installation being tested.
The identity and demo charts reject empty required values.

For an existing SPIRE installation, read its reconciled configuration:

```sh
TRUST_DOMAIN="$(oc get zerotrustworkloadidentitymanagers.operator.openshift.io cluster -o jsonpath='{.spec.trustDomain}')"
SPIFFE_ISSUER="$(oc get spireoidcdiscoveryproviders.operator.openshift.io cluster -o jsonpath='{.spec.jwtIssuer}')"
```

Use a dedicated namespace and VM, for example `saw-identity-test` and
`identity-test`. Pick a unique `TEST_RUN_ID` for each live run. The optional
demo issuer must allow only the SAW prefix being tested:

```sh
SAW_NAMESPACE=saw-identity-test
SAW_NAME=identity-test
TEST_RUN_ID=agent-identity-test-1
helm upgrade --install identity-demo charts/identity-demo \
  --namespace saw-identity-demo --create-namespace \
  -f examples/agent-identity/demo-values.yaml \
  --set-string "spiffeIssuer=$SPIFFE_ISSUER" \
  --set-string "allowedPrefixes[0]=spiffe://$TRUST_DOMAIN/saw/$SAW_NAMESPACE/$SAW_NAME"
```

Before installing the demo, create a random, run-specific Secret named
`identity-demo-enrollment` in `saw-identity-demo`, with a `token` key. Keep the
token out of Git, Helm values, shell arguments, and logs. If the demo
namespace or the cluster DNS suffix differs from the
example, also set the chart's `issuer` and update the demo host in the SAW
provider profile. `provider-values.yaml` and `bom-values.yaml` use the
example's `saw-identity-demo` namespace and standard `cluster.local` DNS.

For a dedicated Pattern SAW, render the Application template with your own
repository and revision, then inspect the output before applying it:

```sh
python3 scripts/render-agent-identity-applications.py \
  --saw-name "$SAW_NAME" \
  --saw-namespace "$SAW_NAMESPACE" \
  --git-repo-url 'https://github.com/YOUR-ORG/secure-agent-workspace.git' \
  --git-revision YOUR-REVISION \
  --trust-domain "$TRUST_DOMAIN" \
  --test-run-id "$TEST_RUN_ID" \
  --output /tmp/agent-identity-applications.yaml
oc apply -f /tmp/agent-identity-applications.yaml
```

The renderer accepts `--gitops-namespace`, `--spire-server-address`, and
`--demo-host` when those names differ. It creates only the dedicated SAW
namespace and its two Applications. It does not adopt the shared SPIRE stack
or another SAW. The target revision must contain the identity charts and a
published registrar image.

For a new shared SPIRE installation, fill the required fields in a site
values file based on `cluster-values.yaml`: `spiffe.trustDomain`,
`spiffe.clusterName`, and `spiffe.jwtIssuer`. Select a storage class for the
server PVC if the cluster default is unsuitable. Point `pattern-values.yaml`
at that site values file in your fork. Do not apply a second owner to an
already installed SPIRE stack. For a direct canary install, supply a unique
`spiffe.testRunID` and the same installed `spiffe.trustDomain` alongside
`canary-values.yaml`.

The quickstart can deploy a dynamic-provider SAW without an API key. Its
`SAW_VALUES` accepts comma-separated Helm values files in precedence order;
put the site values last. For example, after setting `TRUST_DOMAIN`,
`SAW_NAME`, and `TEST_RUN_ID` above:

```sh
cat > /tmp/agent-identity-site-values.yaml <<EOF
spiffe:
  trustDomain: "$TRUST_DOMAIN"
  testRunID: "$TEST_RUN_ID"
EOF
make openshell-saw-create \
  OPENSHELL_SAW_NAME="$SAW_NAME" SAW_NS="$SAW_NAMESPACE" \
  OWNER=identity-test OIDC_ISSUER=none DYNAMIC_PROVIDERS=true \
  SAW_VALUES="examples/agent-identity/canary-values.yaml,examples/agent-identity/provider-values.yaml,/tmp/agent-identity-site-values.yaml" \
  SAW_BOM_VALUES=examples/agent-identity/bom-values.yaml
```

The demo issuer must allow this SAW's SPIFFE prefix before protected requests
can succeed. The quickstart leaves route, governance, and inference settings
to these values files in dynamic mode. Remove the test VM and its namespace
after recording evidence.
