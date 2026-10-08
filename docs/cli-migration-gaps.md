# CLI migration review

The repository has a Click CLI at `cli/src/openshell_saw/cli.py`. Its
command is `openshell-saw`. Keep the full Make to CLI migration in separate
work. Validated Pattern entry points remain `make install` and
`make pattern-uninstall`.

## Current coverage

The CLI has `login`, `whoami`, `status`, `sandbox create`, `sandbox list`,
`sandbox delete`, `sandbox ssh`, `sandbox logs`, `sandbox url`,
`build gateway-image`, and `build gateway-image-logs`. The current Make
interface also covers the operations below.

| Operation | Current CLI gap |
|---|---|
| SAW-BOM profiles | `sandbox create` has no profile selection. |
| Custom inference | No endpoint URL, profile, or service account file option. |
| Owner identity | The CLI reads the signed-in subject, but has no explicit owner subject option for an admin creating another user's SAW. |
| Namespace deletion | `sandbox delete` uninstalls Helm and keeps the namespace. `saw-delete` deletes a namespace with the SAW ownership label. |
| Gateway setup | No command for CA extraction, gateway registration, and selection. |
| TUI and GUI | No commands to start either UI or own the GUI forward. |
| Images | No image mirror, sandbox image, CLI image, or governance interceptor build command. The gateway build command covers one image only. |
| Governance | No policy deploy, profile list, add, remove, or create commands. |
| Credentials | `sandbox create --api-key` places a key in the command arguments. The Make path reads it from the environment. |

The CLI also needs the same 19-character DNS label validation as Make,
clear errors for missing resources versus access failures, and tests for
idempotent deletion. Do not make it the default interface until these gaps
are closed and the UX review is complete.

## UX review input

The proposed Make command pattern is component-action:

```text
make prereqs-check
make quickstart-prereqs-check
make ssh-key-generate
make images-mirror
make gateway-build CONTAINER_RUNTIME=podman
make keycloak-deploy
make governance-deploy
make saw-create OPENSHELL_SAW_NAME=alice
make saw-status OPENSHELL_SAW_NAME=alice
make saw-list
make pattern-uninstall
```

`make help` groups the targets and lists old names as aliases for one
release. Each alias prints `Warning: <old> is deprecated. Use <new>.`.
These error examples show the intended tone and the missing action:

```text
Error: OPENSHELL_SAW_NAME is required. Pass OPENSHELL_SAW_NAME=my-saw.
Error: OPENSHELL_SAW_NAME must be a lowercase DNS label of at most 19 characters.
Error: CONTAINER_RUNTIME must be podman or docker.
Error: KC_USER is required. Pass KC_USER=alice.
Error: local port 18789 is in use. Set GUI_PORT to a free port.
```

## Usability review: 2026-10-08

An internal review checked the live `make help` output, safe error paths,
the alias list, and the quickstart and Pattern examples. It found:

| Finding | Decision |
|---|---|
| `prereqs-check` used to require operators that the Pattern installs. | Keep this target for tools and cluster capacity. Use `quickstart-prereqs-check` when CNV and RHBK must already exist. |
| Keycloak help said new passwords were printed, but the script stores them in a Secret. | Correct the help and README. Document how Alice and Bob can copy their own test password without terminal output. |
| Missing `KC_USER` printed only `Set KC_USER=<name>.` | Give an error and a complete example for password, reset, and register. |
| `saw-list` said it listed sandboxes, but it lists SAW virtual machines. | Correct the help text. |
| Internal checks appeared before the public setup commands. | Move them after the public help sections. |

The component-action names are consistent across the main day-two targets.
The old names remain aliases for one release. Their warning names the
replacement. Missing SAW name, invalid SAW name, and invalid container
runtime errors state the required fix. The help output still begins with
framework tasks and is long. A designer should decide whether a short
beginner view would help new users.

This is an internal usability review. No UX designer approval is recorded.
The UX designer still needs to review the names, help order, variable text,
and errors before the interface is finalized. Record that decision before
release. The CLI should keep the same terms when a migration starts.
