NS             ?= openshell-agents
SANDBOX_NAME   ?= my-sandbox
AGENT          ?= openclaw
PROVIDER       ?=
MODEL          ?=
API_KEY        ?=
ENDPOINT_URL   ?=
WEB_SEARCH     ?=
GCP_SA_JSON    ?=
OIDC_ISSUER    ?=
OIDC_CLIENT_ID ?= openshell-cli
OIDC_FLOW      ?= browser
OIDC_TOKEN_DIR ?= $(HOME)/.config/openshell/oidc
SSH_KEY_PATH   ?= $(HOME)/.ssh/id_ed25519
OWNER          ?=
NAMESPACE_MODE ?= shared
HELM_DIR       := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

SSH_PUBKEY = $(shell cat "$(SSH_KEY_PATH).pub" 2>/dev/null)

.check-ssh-key:
	@test -f "$(SSH_KEY_PATH).pub" || { \
		echo "Error: SSH key not found at $(SSH_KEY_PATH).pub"; \
		echo "Set SSH_KEY_PATH to your key path, e.g.: make gateway SSH_KEY_PATH=~/.ssh/my_key"; \
		exit 1; \
	}


.PHONY: help build build-logs build-cli build-cli-logs \
        build-gateway-image build-gateway-image-logs \
        keycloak keycloak-issuer login whoami logout teardown-keycloak \
        gateway gateway-test gateway-verify \
        sandbox-create list-sandboxes sandbox-logs sandbox-ssh ssh-secret \
        openshell-configure-gateway \
        tui gui \
        delete-sandbox delete-gateway delete-all status \
        .check-ssh-key

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- NemoClaw image ---

build: ## Install nemoclaw-imagestream chart and start a build
	helm upgrade --install nemoclaw-imagestream $(HELM_DIR)nemoclaw-imagestream \
		--namespace $(NS) --create-namespace
	oc start-build nemoclaw-sandbox -n $(NS) --follow

build-logs: ## Follow the latest NemoClaw image build logs
	oc logs -f bc/nemoclaw-sandbox -n $(NS)

# --- NemoClaw CLI image ---

build-cli: ## Install nemoclaw-cli-imagestream chart and start a CLI build
	helm upgrade --install nemoclaw-cli-imagestream $(HELM_DIR)nemoclaw-cli-imagestream \
		--namespace $(NS) --create-namespace
	oc start-build nemoclaw-cli -n $(NS) --follow

build-cli-logs: ## Follow the latest NemoClaw CLI image build logs
	oc logs -f bc/nemoclaw-cli -n $(NS)

# --- Gateway VM image ---

build-gateway-image: ## Build the bootc gateway VM image
	helm upgrade --install openshell-gateway-image $(HELM_DIR)openshell-gateway-image \
		--namespace $(NS) --create-namespace
	oc start-build openshell-gateway -n $(NS) --follow

build-gateway-image-logs: ## Follow the latest gateway image build logs
	oc logs -f bc/openshell-gateway -n $(NS)

# --- Keycloak / OIDC ---

keycloak: ## Deploy Keycloak OIDC provider (for local testing)
	@echo "Deploying Keycloak..."
	helm upgrade --install openshell-keycloak $(HELM_DIR)openshell-keycloak \
		--namespace $(NS) --create-namespace \
		--timeout 10m
	@echo "Waiting for Keycloak rollout..."
	kubectl rollout status deployment/openshell-keycloak -n $(NS) --timeout=5m
	@echo "Keycloak deployed."

keycloak-issuer: ## Print the Keycloak OIDC issuer URL
	@host=$$(oc get route openshell-keycloak -n $(NS) -o jsonpath='{.spec.host}' 2>/dev/null); \
	if [ -z "$${host}" ]; then \
		echo "Error: Keycloak Route not found. Run 'make keycloak' first." >&2; \
		exit 1; \
	fi; \
	echo "https://$${host}/realms/openshell"

login: ## Authenticate with the OIDC provider
	@OIDC_ISSUER=$(OIDC_ISSUER) \
	OIDC_CLIENT_ID=$(OIDC_CLIENT_ID) \
	OIDC_FLOW=$(OIDC_FLOW) \
	OIDC_TOKEN_DIR=$(OIDC_TOKEN_DIR) \
	NS=$(NS) \
	$(HELM_DIR)../scripts/oidc-login.sh login

whoami: ## Show current OIDC identity and token status
	@OIDC_TOKEN_DIR=$(OIDC_TOKEN_DIR) \
	$(HELM_DIR)../scripts/oidc-login.sh whoami

logout: ## Revoke OIDC token and clear credentials (local + sandboxes)
	@OIDC_CLIENT_ID=$(OIDC_CLIENT_ID) \
	OIDC_TOKEN_DIR=$(OIDC_TOKEN_DIR) \
	$(HELM_DIR)../scripts/oidc-login.sh logout
	@echo "Clearing OIDC tokens from running sandboxes..."
	@helm list -n $(NS) --filter '.*' -o json 2>/dev/null \
		| jq -r '.[] | select(.chart | startswith("openshell-sandbox")) | .name' 2>/dev/null \
		| while read -r sb; do \
			echo "  $$sb: clearing token..."; \
			virtctl -n $(NS) ssh cloud-user@vm/$$sb \
				--local-ssh-opts="-oStrictHostKeyChecking=no" \
				--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
				--local-ssh-opts="-oConnectTimeout=5" \
				--command="sudo rm -f /etc/openshell/gateway.toml ~/.config/openshell/gateway.toml && sudo systemctl restart openshell-gateway-setup.service" \
				2>/dev/null && echo "  $$sb: done" || echo "  $$sb: skipped (VM unreachable)"; \
		done
	@echo "Logout complete."

teardown-keycloak: ## Uninstall Keycloak
	helm uninstall openshell-keycloak --namespace $(NS)

# --- Gateway ---

gateway: .check-ssh-key ## Deploy a gateway VM from the pre-built bootc image
	@echo "Deploying gateway from bootc image..."
	helm upgrade --install openshell-gateway $(HELM_DIR)openshell-gateway \
		--namespace $(NS) --create-namespace \
		--set sshPublicKey="$(SSH_PUBKEY)" \
		--set image.containerDisk=image-registry.openshift-image-registry.svc:5000/$(NS)/openshell-gateway:latest \
		$(if $(OIDC_ISSUER),--set oidc.enabled=true --set oidc.issuerUrl=$(OIDC_ISSUER) --set oidc.clientId=$(OIDC_CLIENT_ID)) \
		--timeout 15m
	@echo "Gateway deployed."

gateway-test: ## Run the gateway helm test (streams logs separately)
	@echo "Starting helm test in background..."
	@helm test openshell-gateway -n $(NS) --logs &
	@sleep 5
	@echo "Streaming test pod logs (Ctrl-C to stop):"
	@kubectl logs -f openshell-gateway-cloud-init-test -n $(NS) 2>/dev/null || \
		echo "Test pod not ready yet. Retry in a few seconds."

gateway-verify: ## Run the standalone gateway verification script
	$(HELM_DIR)openshell-gateway/verify.sh openshell-gateway $(NS)

# --- SSH secret ---

ssh-secret: ## Create the SSH private key secret for sandbox Jobs
	oc -n $(NS) create secret generic openshell-aap-ssh \
		--from-file=key=$(SSH_KEY_PATH) \
		--dry-run=client -o yaml | oc apply -f -

# --- Sandbox ---

sandbox-create: .check-ssh-key ssh-secret ## Provision a sandbox (PROVIDER=, MODEL=, API_KEY=, SANDBOX_NAME=)
ifeq ($(PROVIDER),)
ifeq ($(GCP_SA_JSON),)
	@echo "Error: PROVIDER or GCP_SA_JSON is required."
	@echo ""
	@echo "Usage:"
	@echo "  make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>"
	@echo ""
	@echo "Providers: gemini, anthropic, openai, build (NVIDIA), openrouter, ollama, custom"
	@exit 1
endif
endif
ifneq ($(GCP_SA_JSON),)
	@test -f "$(GCP_SA_JSON)" || { echo "Error: file not found: $(GCP_SA_JSON)"; exit 1; }
endif
	@oc whoami >/dev/null 2>&1 || { echo "Error: Not logged in to OpenShift. Run 'oc login' first."; exit 1; }; \
	OWNER="$(OWNER)"; \
	if [ -z "$$OWNER" ]; then \
		KC_USER=$$(jq -r '.access_token // empty' $(OIDC_TOKEN_DIR)/token.json 2>/dev/null \
			| python3 -c "import sys,base64,json; t=sys.stdin.read().strip().split('.')[1]; t+='='*(4-len(t)%4); print(json.loads(base64.urlsafe_b64decode(t)).get('preferred_username',''))" 2>/dev/null); \
		if [ -z "$$KC_USER" ]; then \
			echo "Error: Not authenticated. Run 'make login' to sign in before creating a sandbox."; \
			exit 1; \
		fi; \
		printf "Logged in as '\033[1m%s\033[0m'\n" "$$KC_USER"; \
		printf "Press Enter to set owner to '$$KC_USER', or type a different owner: "; \
		read -r INPUT_OWNER; \
		if [ -n "$$INPUT_OWNER" ]; then \
			OWNER="$$INPUT_OWNER"; \
		else \
			OWNER="$$KC_USER"; \
		fi; \
	fi; \
	OIDC_ISSUER="$(OIDC_ISSUER)"; \
	if [ -z "$$OIDC_ISSUER" ]; then \
		OIDC_ISSUER=$$(helm get values openshell-gateway -n $(NS) -o json 2>/dev/null | jq -r 'if .oidc.enabled then .oidc.issuerUrl // empty else empty end' 2>/dev/null); \
	fi; \
	if [ -z "$$OIDC_ISSUER" ]; then \
		KC_HOST=$$(oc get route openshell-keycloak -n $(NS) -o jsonpath='{.spec.host}' 2>/dev/null); \
		if [ -n "$$KC_HOST" ]; then \
			OIDC_ISSUER="https://$$KC_HOST/realms/openshell"; \
		fi; \
	fi; \
	OIDC_OPTS=""; \
	if [ -n "$$OIDC_ISSUER" ]; then \
		OIDC_OPTS="--set oidc.issuerUrl=$$OIDC_ISSUER --set oidc.clientId=$(OIDC_CLIENT_ID)"; \
		OIDC_TOKEN=$$(OIDC_TOKEN_DIR=$(OIDC_TOKEN_DIR) OIDC_CLIENT_ID=$(OIDC_CLIENT_ID) OIDC_ISSUER=$$OIDC_ISSUER NS=$(NS) $(HELM_DIR)../scripts/oidc-login.sh token 2>/dev/null); \
		if [ -n "$$OIDC_TOKEN" ]; then \
			OIDC_OPTS="$$OIDC_OPTS --set-string oidc.token=$$OIDC_TOKEN"; \
		fi; \
	fi; \
	AC_OPTS="--set accessControl.enabled=true --set accessControl.owner=$$OWNER"; \
	DEPLOY_NS="$(NS)"; \
	if [ "$(NAMESPACE_MODE)" = "perUser" ]; then \
		DEPLOY_NS="saw-$$(echo "$$OWNER" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | cut -c1-58)"; \
		oc create namespace "$$DEPLOY_NS" --dry-run=client -o yaml | oc apply -f - 2>/dev/null; \
	fi; \
	echo "Provisioning sandbox '$(SANDBOX_NAME)' for owner '$$OWNER' in namespace '$$DEPLOY_NS'..."; \
	helm upgrade --install $(SANDBOX_NAME) $(HELM_DIR)openshell-sandbox \
		--namespace $$DEPLOY_NS --create-namespace \
		--set sandboxName=$(SANDBOX_NAME) \
		--set sshPublicKey="$(SSH_PUBKEY)" \
		--set agent=$(AGENT) \
		--set inference.provider=$(PROVIDER) \
		--set inference.model=$(MODEL) \
		--set inference.apiKey=$(API_KEY) \
		--set inference.endpointUrl=$(ENDPOINT_URL) \
		--set inference.webSearch=$(WEB_SEARCH) \
		$(if $(GCP_SA_JSON),--set-file vertexSaJson=$(GCP_SA_JSON)) \
		$$OIDC_OPTS \
		$$AC_OPTS \
		--set namespaceMode=$(NAMESPACE_MODE) \
		\
		--set route.enabled=true --set route.dashboard=true; \
	echo ""; \
	echo "Sandbox '$(SANDBOX_NAME)' deployed."; \
	echo "  Owner:     $$OWNER"; \
	echo "  Namespace: $$DEPLOY_NS"; \
	GW_URL=$$(oc get route $(SANDBOX_NAME)-gateway -n $$DEPLOY_NS -o jsonpath='https://{.spec.host}' 2>/dev/null); \
	if [ -n "$$GW_URL" ]; then \
		echo "  Gateway:   $$GW_URL"; \
	fi; \
	DASH_URL=$$(oc get route $(SANDBOX_NAME)-dashboard -n $$DEPLOY_NS -o jsonpath='https://{.spec.host}' 2>/dev/null); \
	if [ -n "$$DASH_URL" ]; then \
		echo "  Dashboard: $$DASH_URL"; \
	fi; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. make openshell-configure-gateway SANDBOX_NAME=$(SANDBOX_NAME) NS=$$DEPLOY_NS"; \
	echo "  2. openshell gateway login"; \
	echo "  3. openshell sandbox list"

openshell-configure-gateway: ## Configure local openshell CLI to use a sandbox gateway (SANDBOX_NAME=)
	@command -v openshell >/dev/null 2>&1 || { \
		echo "Error: openshell CLI not found."; \
		echo "Install it from: https://github.com/NVIDIA/OpenShell/releases"; \
		exit 1; \
	}
	@GW_URL=$$(oc get route $(SANDBOX_NAME)-gateway -n $(NS) -o jsonpath='https://{.spec.host}' 2>/dev/null); \
	if [ -z "$$GW_URL" ]; then \
		echo "Error: Gateway route not found for sandbox '$(SANDBOX_NAME)' in namespace '$(NS)'."; \
		exit 1; \
	fi; \
	OIDC_ISSUER="$(OIDC_ISSUER)"; \
	if [ -z "$$OIDC_ISSUER" ]; then \
		OIDC_ISSUER=$$(helm get values openshell-gateway -n $(NS) -o json 2>/dev/null | jq -r 'if .oidc.enabled then .oidc.issuerUrl // empty else empty end' 2>/dev/null); \
	fi; \
	if [ -z "$$OIDC_ISSUER" ]; then \
		KC_HOST=$$(oc get route openshell-keycloak -n $(NS) -o jsonpath='{.spec.host}' 2>/dev/null); \
		if [ -n "$$KC_HOST" ]; then \
			OIDC_ISSUER="https://$$KC_HOST/realms/openshell"; \
		fi; \
	fi; \
	OIDC_OPTS=""; \
	if [ -n "$$OIDC_ISSUER" ]; then \
		OIDC_OPTS="--oidc-issuer $$OIDC_ISSUER --oidc-client-id $(OIDC_CLIENT_ID)"; \
	fi; \
	echo "Registering gateway '$(SANDBOX_NAME)'..."; \
	openshell gateway add "$$GW_URL" --name $(SANDBOX_NAME) --gateway-insecure $$OIDC_OPTS; \
	openshell gateway select $(SANDBOX_NAME); \
	echo ""; \
	echo "Gateway '$(SANDBOX_NAME)' configured and selected."; \
	echo "  Endpoint: $$GW_URL"; \
	if [ -n "$$OIDC_ISSUER" ]; then \
		echo "  Auth:     OIDC ($$OIDC_ISSUER)"; \
		echo ""; \
		echo "Next: openshell gateway login"; \
	fi

list-sandboxes: ## List all sandboxes
	@printf "%-20s %-12s %-10s %s\n" "NAME" "STATUS" "VM" "CREATED"
	@helm list -n $(NS) --filter '.*' -o json 2>/dev/null | jq -r '.[] | select(.chart | startswith("openshell-sandbox")) | .name' 2>/dev/null | while read -r name; do \
		status=$$(helm status "$$name" -n $(NS) -o json 2>/dev/null | jq -r '.info.status // "unknown"'); \
		vm_status=$$(kubectl get vm "$$name" -n $(NS) -o jsonpath='{.status.printableStatus}' 2>/dev/null || echo "n/a"); \
		created=$$(helm list -n $(NS) --filter "^$${name}$$" -o json 2>/dev/null | jq -r '.[0].updated | split(".")[0]' 2>/dev/null); \
		printf "%-20s %-12s %-10s %s\n" "$$name" "$$status" "$$vm_status" "$$created"; \
	done

sandbox-logs: ## Follow sandbox setup Job logs (SANDBOX_NAME=)
	oc -n $(NS) logs -f job/$(SANDBOX_NAME)-setup

sandbox-ssh: ## SSH into a sandbox VM for debugging (SANDBOX_NAME=)
	@ssh-keygen -R vm.$(SANDBOX_NAME).$(NS) 2>/dev/null || true
	virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME)

# --- User access ---

tui: ## Launch OpenClaw TUI in a sandbox (SANDBOX_NAME=)
	@ssh-keygen -R vm.$(SANDBOX_NAME).$(NS) 2>/dev/null || true
	virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME) \
		--local-ssh-opts="-oStrictHostKeyChecking=no" \
		--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
		--local-ssh-opts="-tt" \
		--command="ssh -o 'ProxyCommand=openshell ssh-proxy --gateway-name openshell --name $(SANDBOX_NAME) --workspace default' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -tt sandbox@openshell-$(SANDBOX_NAME).default openclaw"

GUI_PORT ?= 18789

gui: ## Open OpenClaw web UI with port-forward (SANDBOX_NAME=, GUI_PORT=18789)
	@pids=$$(lsof -ti :$(GUI_PORT) 2>/dev/null) && [ -n "$$pids" ] && kill $$pids && sleep 1 || true
	@ssh-keygen -R vm.$(SANDBOX_NAME).$(NS) 2>/dev/null || true
	@virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME) \
		--local-ssh-opts="-oStrictHostKeyChecking=no" \
		--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
		--local-ssh-opts="-oConnectTimeout=15" \
		--command="pkill -f 'ssh.*-L.*$(GUI_PORT)'" 2>/dev/null || true
	@echo "Fetching dashboard token..." && \
	TOKEN=$$(virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME) \
		--local-ssh-opts="-oStrictHostKeyChecking=no" \
		--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
		--local-ssh-opts="-oConnectTimeout=15" \
		--command="cat ~/.openclaw-token-$(SANDBOX_NAME) 2>/dev/null" 2>/dev/null | tr -d '[:space:]') && \
	if [ -z "$${TOKEN}" ]; then \
		DASHBOARD_URL=$$(virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME) \
			--local-ssh-opts="-oStrictHostKeyChecking=no" \
			--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
			--local-ssh-opts="-oConnectTimeout=15" \
			--command="nemoclaw sandbox dashboard-url $(SANDBOX_NAME)" 2>/dev/null | grep -o 'http[^ ]*' | tail -1) && \
		TOKEN=$$(echo "$${DASHBOARD_URL}" | grep -o '#token=.*' | sed 's/#token=//'); \
	fi && \
	test -n "$${TOKEN}" && \
	echo "" && \
	echo "OpenClaw UI: http://localhost:$(GUI_PORT)/#token=$${TOKEN}" && \
	echo "Press Ctrl-C to stop." && \
	echo "" && \
	virtctl -n $(NS) ssh cloud-user@vm/$(SANDBOX_NAME) \
		--local-ssh-opts="-oStrictHostKeyChecking=no" \
		--local-ssh-opts="-oUserKnownHostsFile=/dev/null" \
		--local-ssh-opts="-L$(GUI_PORT):127.0.0.1:$(GUI_PORT)" \
		--command="ssh -o 'ProxyCommand=openshell ssh-proxy --gateway-name openshell --name $(SANDBOX_NAME) --workspace default' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -L $(GUI_PORT):127.0.0.1:18789 -N sandbox@openshell-$(SANDBOX_NAME).default"

# --- Teardown ---

delete-sandbox: ## Uninstall a sandbox (SANDBOX_NAME=)
	helm uninstall $(SANDBOX_NAME) --namespace $(NS)

delete-gateway: ## Uninstall the gateway
	helm uninstall openshell-gateway --namespace $(NS)

delete-all: ## Uninstall everything (gateway + keycloak + imagestreams)
	-helm uninstall openshell-gateway --namespace $(NS) 2>/dev/null
	-helm uninstall openshell-keycloak --namespace $(NS) 2>/dev/null
	-helm uninstall openshell-gateway-image --namespace $(NS) 2>/dev/null
	-helm uninstall nemoclaw-imagestream --namespace $(NS) 2>/dev/null
	-helm uninstall nemoclaw-cli-imagestream --namespace $(NS) 2>/dev/null
	@echo "Note: sandbox releases must be uninstalled individually."

# --- Status ---

status: ## Show status of all OpenShell resources
	@echo "=== Helm releases ==="
	@helm list -n $(NS) 2>/dev/null || true
	@echo ""
	@echo "=== VMs ==="
	@oc -n $(NS) get vm 2>/dev/null || true
	@echo ""
	@echo "=== VMIs ==="
	@oc -n $(NS) get vmi 2>/dev/null || true
	@echo ""
	@echo "=== ImageStreams ==="
	@oc -n $(NS) get is 2>/dev/null || true
	@echo ""
	@echo "=== Builds ==="
	@oc -n $(NS) get builds 2>/dev/null || true
	@echo ""
	@echo "=== Jobs ==="
	@oc -n $(NS) get jobs 2>/dev/null || true
