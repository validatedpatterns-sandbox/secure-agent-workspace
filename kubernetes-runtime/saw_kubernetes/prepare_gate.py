"""Publish the shared tool-gate tree on its dedicated PVC before workspace startup."""
import argparse
import fcntl
import json
import re
import os
from pathlib import Path
import tempfile

from .core import shared


def verify(directory, files, model_selector=False):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid gate directory")
    dirs = {p for item in files for p in Path(item).parents} - {Path(".")}
    for path in directory.rglob("*"):
        rel = path.relative_to(directory)
        if model_selector and rel.as_posix()=="model.json" and path.is_file() and not path.is_symlink():
            continue
        if path.is_symlink() or (rel not in dirs if path.is_dir() else rel.as_posix() not in files):
            raise ValueError("unexpected entry in the trusted gate")
    for rel, (data, _) in files.items():
        path = directory / rel
        if not path.is_file() or path.read_bytes() != data:
            raise ValueError("existing gate differs from the requested policy or owner")


def publish(root, identity, receipt_key=None, *, model=None, generation=None):
    assets = Path(shared.__file__).parent
    files, _, digest, _ = shared.tool_gate_bundle(assets, identity, receipt_key)
    target = root / "bundle"
    publish_tree(root, target, files, model_selector=model is not None)
    if model is not None:
        publish_model(root, target, model, generation)
    return digest


def publish_tree(root, target, files, *, model_selector=False):
    if not target.exists():
        with tempfile.TemporaryDirectory(dir=root) as scratch:
            tmp = Path(scratch) / "bundle"
            tmp.mkdir(mode=0o755)
            for rel, (data, _) in files.items():
                path = tmp / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o444)
            # The final nonempty tree is never overwritten, including concurrent publishers.
            try:
                tmp.rename(target)
            except FileExistsError:
                pass
            except OSError:
                if not target.is_dir():
                    raise
    verify(target, files, model_selector=model_selector)


def publish_harness(root, bom, name, expected_digest):
    from .harness import bundle_tree, read_bundles
    _, raw, index = shared.read_profile_files(bom)
    bundle = read_bundles(raw, index).get(name)
    if not bundle or bundle.name != name or bundle.digest != expected_digest:
        raise ValueError("mounted BOM does not match enrolled harness")
    publish_tree(root, root / ("harness-" + bundle.digest.removeprefix("sha256:")), bundle_tree(bundle))


def publish_model(root, target, model, generation):
    """Fence concurrent or replayed GitOps Jobs on the per-sandbox gate volume."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}", model) or type(generation) is not int or generation < 1:
        raise ValueError("invalid model selection")
    selected = {"generation":generation, "model":model}
    path = target / "model.json"
    with (root / ".model-lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            previous = json.loads(path.read_text())
            if previous["generation"] > generation:
                return  # A newer publication already won.
            if previous["generation"] == generation:
                if previous != selected:
                    raise ValueError("conflicting model at the same generation")
                return
        with tempfile.NamedTemporaryFile(dir=root, mode="w", delete=False) as tmp:
            try:
                json.dump(selected, tmp)
                tmp.flush()
                os.fchmod(tmp.fileno(), 0o444)
                os.fsync(tmp.fileno())
                os.replace(tmp.name, path)
            finally:
                Path(tmp.name).unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("owner", "subject", "workspace", "sandbox"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--harness", nargs=2, metavar=("NAME", "DIGEST"))
    parser.add_argument("--model")
    parser.add_argument("--model-generation",type=int)
    receipt = parser.add_mutually_exclusive_group()
    receipt.add_argument("--receipt-key")
    receipt.add_argument("--writer-service")
    parser.add_argument("--writer-namespace")
    parser.add_argument("--writer-ca")
    args = parser.parse_args()
    if args.writer_service:
        from .receipt import receipt_key
        args.receipt_key = receipt_key(args.writer_service, args.writer_namespace, args.writer_ca)
    os.umask(0o022)
    if args.harness:
        publish_harness(Path("/volume"), Path("/bom"), *args.harness)
    print(publish(Path("/volume"), shared.tool_gate_identity(args.owner, args.subject, args.workspace, args.sandbox), args.receipt_key, model=args.model, generation=args.model_generation))
