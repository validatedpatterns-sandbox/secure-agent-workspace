# Render with scripts/render-agent-identity-applications.py before applying.
# This creates one dedicated SAW and BOM Application. It does not install or
# adopt the shared SPIRE stack or an existing SAW.
apiVersion: v1
kind: Namespace
metadata:
  name: ${SAW_NAMESPACE}
  labels:
    openshell.pattern/saw: "true"
    saw.redhat.com/identity-test-run: ${TEST_RUN_ID}
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${SAW_BOM_NAME}
  namespace: ${GITOPS_NAMESPACE}
  labels:
    validatedpatterns.io/pattern: secure-agent-workspace
    openshell.pattern/owner: ${SAW_NAME}
spec:
  project: default
  destination:
    name: in-cluster
    namespace: ${SAW_NAMESPACE}
  source:
    repoURL: ${GIT_REPO_URL}
    targetRevision: ${GIT_REVISION}
    path: charts/saw-bom
    helm:
      releaseName: saw-bom
      values: |
        profiles: []
        profileFiles:
          profiles/identity-demo/default/providers.yaml: |
            apiVersion: saw.redhat.com/v1alpha1
            kind: Providers
            spec:
              providers:
              - name: protected
                runtimeCredentials: true
                type: saw-demo-cc
          profiles/identity-demo/default/sandbox.yaml: |
            apiVersion: saw.redhat.com/v1alpha1
            kind: Sandboxes
            spec:
              sandboxes:
              # UBI supplies sh and curl without an incompatible image policy.
              - image: registry.access.redhat.com/ubi9/ubi@sha256:dec374e05cc13ebbc0975c9f521f3db6942d27f8ccdf06b180160490eef8bdbc
                name: agent
                providers:
                - protected
                type: generic
          profiles/identity-demo/default/workspace.yaml: |
            apiVersion: saw.redhat.com/v1alpha1
            kind: Workspace
            metadata:
              name: default
            spec:
              enabled: true
  syncPolicy:
    automated:
      selfHeal: true
      prune: true
    retry:
      limit: 5
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${SAW_NAME}
  namespace: ${GITOPS_NAMESPACE}
  labels:
    validatedpatterns.io/pattern: secure-agent-workspace
    openshell.pattern/owner: ${SAW_NAME}
spec:
  project: default
  destination:
    name: in-cluster
    namespace: ${SAW_NAMESPACE}
  source:
    repoURL: ${GIT_REPO_URL}
    targetRevision: ${GIT_REVISION}
    path: charts/openshell-saw
    helm:
      releaseName: ${SAW_NAME}
      values: |
        sandboxName: ${SAW_NAME}
        route:
          enabled: false
          dashboard: false
        governance:
          enabled: false
        dashboard:
          enabled: false
        vm:
          cores: 2
          memory: 4Gi
          readinessProbe: true
        spiffe:
          enabled: true
          testMode: true
          testRunID: ${TEST_RUN_ID}
          trustDomain: ${TRUST_DOMAIN}
          serverAddress: ${SPIRE_SERVER_ADDRESS}
          serverPort: 443
          serverTransport: tcp
          gatewayUID: 1000
        providerProfiles:
          saw-demo-cc:
            id: saw-demo-cc
            display_name: SAW identity acceptance
            category: other
            credentials:
            - name: access_token
              required: false
              auth_style: bearer
              header_name: Authorization
              token_grant:
                grant_type: client_credentials
                token_endpoint: ${DEMO_TOKEN_ENDPOINT}
                audience: saw-protected-service
                jwt_svid_audience: ${DEMO_AUDIENCE}
                cache_ttl_seconds: 30
            endpoints:
            - host: ${DEMO_HOST}
              port: 8080
              protocol: rest
              access: read-write
              enforcement: enforce
            binaries:
            - /usr/bin/curl
  ignoreDifferences:
    # KubeVirt and the MAC pool write these after admission. Server-side
    # apply does not take them, and a Healthy status does not mean the
    # chart spec matches. The registrar finalizer is checked on the VM.
    - group: kubevirt.io
      kind: VirtualMachine
      jsonPointers:
        - /metadata/annotations/kubemacpool.io~1transaction-timestamp
        - /metadata/annotations/kubevirt.io~1latest-observed-api-version
        - /metadata/annotations/kubevirt.io~1storage-observed-api-version
        - /metadata/finalizers
        - /spec/template/metadata/annotations/kubevirt.io~1pci-topology-version
        - /spec/template/spec/architecture
        - /spec/template/spec/domain/machine
        - /spec/template/spec/domain/firmware/serial
        - /spec/template/spec/domain/firmware/uuid
        - /spec/template/spec/domain/devices/interfaces/0/macAddress
  syncPolicy:
    automated:
      selfHeal: true
      prune: true
    retry:
      limit: 5
    syncOptions:
      - ServerSideApply=true
