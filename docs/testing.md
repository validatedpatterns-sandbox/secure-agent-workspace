# Writing and running tests

`make test` and `make test-installer` run the same complete pytest suite.
This includes installer, chart, script, portal, credential-proxy binary, and
CLI tests. Node tool-gate checks are part of this suite and run in CI.
These tests need no cluster or real provider keys.

## Local tools and commands

Use `uv` for local Python work. The root `uv.lock` supplies Python test
dependencies. CI keeps its Python and pip setup in `tests/requirements.txt`.
Update both dependency declarations and run `uv lock` when you add a package.

For the complete suite, use Ubuntu 24.04 with Python 3.12 or 3.14, GNU Make,
Bash, Helm 3.17.3, Node 22, Go from `credential-proxy/go.mod`, OpenSSL, Git,
OpenSSH tools, `jq`, `envsubst` (gettext), GNU coreutils (`shred`, `timeout`,
`stat`, `install`), GNU tar, `flock`, and `pgrep`/`pkill`. Some unit checks also
use `systemd-analyze`.
The Go binary check can download Go modules on its first run.
Embedded Rust checks need Cargo and cached `serde_json` dependencies. They
report a skip if those dependencies are absent; the image build runs them too.

Use Linux for acceptance runs. PKI cleanup uses `shred`, process checks use
`/proc`, and archive ownership checks need GNU tools. A macOS run can test
focused portable behavior, but cannot replace a Linux run. Do not add a fake
`shred` or remove Linux checks to make a full host run pass.

Run these commands from the repository root:

```bash
# Install the locked local dependencies.
uv sync --locked

# Complete suite, serial by default. Use either supported target.
make test
make test-installer

# One file.
make test TEST_PATHS=tests/installer/test_profiles.py

# Select cases by name, or run one exact test.
make test TEST_PATHS=tests/installer/test_profiles.py PYTEST_ARGS='-k bad'
make test TEST_PATHS=tests/installer/test_apply_profiles.py::test_shipped_profile_lifecycle

# Explicit serial and two-worker runs.
make test PYTEST_ARGS='-n 0'
make test PYTEST_ARGS='-n 2 --dist=load'

# Include setup and teardown in the duration report. Keep skip reasons.
mkdir -p test-results
make test PYTEST_ARGS='-n 2 --dist=load --durations=40 -ra --junitxml=test-results/local.xml'

# Inspect every setup, call, and teardown for a focused file.
make test TEST_PATHS=tests/installer/test_profiles.py PYTEST_ARGS='--durations=0 --durations-min=0'

# CI selections: external checks once; project Python behavior on both versions.
make lint-static
uv run --python 3.14 --locked make test PYTHON=python PYTEST_ARGS='-m ci_external -n 2 --dist=load'
uv run --python 3.12 --locked make test PYTHON=python PYTEST_ARGS='-m "not ci_external" -n 2 --dist=load'
uv run --python 3.14 --locked make test PYTHON=python PYTEST_ARGS='-m "not ci_external" -n 2 --dist=load'

# Static lint plus the Make interface tests. CI runs the latter through pytest.
make lint
make lint-interface
```

`TEST_PATHS` selects files or pytest node IDs. `PYTEST_ARGS` adds pytest
selection, timing, report, and worker options. `PYTHON` remains an optional
interpreter override. Without it, Make runs `uv run --locked pytest`.
Use `--collect-only` with either marker selection to inspect membership.

## Choose the test level

Use a focused function test for validation, parsing, and decisions. Call the
public behavior under test and check its result. Do not run a full installer
apply to check one invalid field.

Use a subprocess test when the defect involves command arguments, environment
variables, files, exit codes, process lifetime, or shell behavior. These tests
must still execute the real project code. Fake only its external services.

Use a full lifecycle test for contracts between components. The shipped-profile
lifecycle test checks creation, native endpoints, NemoClaw onboarding,
keepalive units, credential markers, and unchanged reapply with one setup.
Keep separate tests for distinct failures and recovery paths.

## Choose small fixtures

Use the smallest profile that exposes the defect. Prune tests need the objects
whose ownership or removal they inspect. A harness test usually needs one
sandbox. Request complete shipped profiles only to check their contract or
interaction between sandboxes.

In installer tests, `fake_commands` provides isolated command state, HOME,
and temporary directories for Python and its child processes.
`fake_env` also copies gateway certificates. `config` adds an admin identity.
Do not request PKI or full installer inputs when a function test needs neither.
Session fixtures share immutable certificate bytes; each test owns its files,
trust bundle, paths, and logs. Dedicated PKI and CLI tests still run real
certificate creation and cleanup.

Chart tests use `helm_cache.run_helm` for local template calls. The cache stores
only successful results. Its key includes chart contents, release, namespace,
arguments, and values-file contents. Helpers parse returned text into private
documents. Do not share mutable dictionaries between tests or cache failures.
Bypass the cache for commands whose external inputs it cannot describe.

## Combine cases and keep assertions effective

Parameterize input variations with clear names. Share one setup when assertions
inspect the same scenario. Keep backup failures, corrupt restore retries,
identity mismatches, and interrupted migrations visible as separate paths.
Parameterization improves structure; it does not by itself reduce runtime.

```python
@pytest.mark.parametrize("value,expected", [
    pytest.param("on", True, id="enabled"),
    pytest.param("off", False, id="disabled"),
])
def test_option(value, expected):
    assert parse_option(value) is expected
```

Supply the value or fault that the assertion checks. To check redaction, pass
an explicit synthetic value and assert that it is absent from output. An
absence check for a value that no fixture supplied proves nothing. For normal
credential-proxy applies, assert marker values and environment-variable names
in arguments. Never use real keys. Derive expected values independently of
the implementation where practical.

## Preserve isolation and control time

Put mutable state in `tmp_path`. Allocate ports dynamically. Keep sockets open
until ownership transfers where possible. Avoid fixed port numbers and shared
repository files. Check default temporary paths too: two tests can use the
same backup name even when their input files are separate. Clean up processes,
child processes, sockets, and threads in `finally` blocks or fixture teardown.
Wait for process exit and thread completion with a bound. Tests must work in
serial and with `-n 2 --dist=load`.

Use `fake_clock` for installer retry and deadline logic. It advances monotonic
time when the code sleeps. A no-op sleep with a real clock can create a busy
loop. Do not use fixed sleeps to synchronize a logic test. Keep real timing for
socket, process-timeout, and lock integration tests. Bound each wait and explain
the real behavior that requires it.

## Maintain fake commands

Reject unsupported commands with a nonzero exit code. Add only the behavior a
test requires and match the supported external command contract. The OpenShell
fake rejects the removed `inference set` and `inference delete` commands.
Do not add success fallbacks that hide unexpected installer calls.

## Select CI coverage

Leave tests unmarked when they execute project Python behavior, including
scripts, CLI code, installer functions, or chart output passed to the installer.
They run on Python 3.12 and 3.14. A new unmarked test automatically enters both
jobs. Directory location does not determine coverage.

Add `@pytest.mark.ci_external` to an individual test only when it checks Helm
output, static assets, Node behavior, or the Go binary without executing
project Python code. Examples are a rendered NetworkPolicy, the Node tool-gate
decision suite, and the credential-proxy binary smoke test. Do not put this
marker on a whole module: a later Python integration test could inherit it.
Test helpers written in Python can drive external tools; this does not make
the external product behavior depend on the project Python runtime.

CI runs static lint and `ci_external` tests once on 3.14. The existing matrix
checks depend on shared checks and fail if those checks fail or are cancelled.
Each test job saves duration output and JUnit results even when tests fail.
The job timeout stays at 30 minutes until measured runs justify a lower value.

## Retire tests and review runtime

Check production support before you remove a test. An old version number or
PR reference does not prove that a migration is obsolete. Keep old-state,
upgrade, certificate-rotation, and restore tests while those paths remain
supported. For each removed test, record where its assertions went or why its
behavior no longer exists. See the [CI test audit](testing-ci-audit.md).

Measure new subprocess tests. Use duration reports that include setup and
teardown, not only test bodies. Explain repeated full applies in the change
description. Compare equal test scope and tool versions. Report skips and
failures separately from performance. Use three comparable CI runs before
and after a runtime change; compare both the longest job and total runner time.

## Contributor checklist

- Name the supported behavior or defect.
- Choose the lowest test level that can expose it.
- Use only the required profile objects and fixtures.
- Supply the value or fault that each assertion checks.
- Isolate files, ports, processes, threads, and mutable state.
- Explain any `ci_external` marker; otherwise use both Python jobs.
- Include timing evidence for costly setup, subprocesses, and repeated applies.

## Credential modes

Helm lint, rendered-shell checks and credential isolation render both modes.
The default proxy render uses the image fixture; direct renders need no image.
`tests/installer/test_credential_modes.py` covers real/named keys, guarded typed
inputs, boot mismatch, volume migrations, fatal provider-update failures,
cleanup ordering and rotation acknowledgement. Lifecycle and PKI contracts
exercise both modes without duplicating the whole suite. Direct Gmail refresh
cases live alongside the proxy and daily-briefing tests.

Use `SKIP_LIVE=1 tests/test-credential-isolation.sh` offline. On a VM, set
`SAW_NS` and `VM_NAME`; the script discovers its mode. Proxy mode checks for key
absence. Direct mode checks the full Secret sources, mode-only compatibility
slot, absent proxy resources/config/CA, and shared gateway/admin hardening.
Live acceptance uses fresh data-science and personal-assistant workspaces in
each mode, then flips all four while checking planted `/sandbox` file hashes,
inference, Slack/Gmail and the rotation warning. Keep the PA test-model override
on a throwaway deployment branch only.
