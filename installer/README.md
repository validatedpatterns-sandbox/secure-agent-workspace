# Versioned SAW installer

`apply_bom.py` is the canonical release implementation. The InstallerBOM chooses
OpenShell versions; this script owns bootstrap, CLI invocation and reconciliation.
The guest runner is version-agnostic and invokes it at
`/opt/saw/installer/apply_bom.py` in the VM. No adapter or vendored API is involved.

The guest bundle and image build consume this source directly. For compatibility,
the legacy saw-bom chart embeds a generated copy under `charts/saw-bom/files/`:

```sh
python3 tools/saw/sync_installer_chart.py
python3 tools/saw/sync_installer_chart.py --check
```

The fast test/CI gate checks freshness. Edit only the canonical source, then
regenerate the chart artifact. Helm packages cannot read files outside their
chart, so the copy is packaging, not a separate implementation.

Pure legacy parser tests live in `installer/tests/`; mounted-path, rootless,
bootstrap and image-build tests live in `tests/saw/`.
