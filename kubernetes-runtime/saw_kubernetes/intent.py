"""Build a controller intent ConfigMap from local observed data; never apply it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import uuid

import yaml

from .compiler import OWNER, canonical, compile_profile_files, digest
from .controller import KEY, MAX_BODY, MAX_DATA, NAME, valid_lifecycle_intent


class IntentError(ValueError):
    """Messages are fixed classifications, never input snippets or credentials."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise IntentError("invalid command-line arguments")


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError()
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _name(value):
    return isinstance(value, str) and len(value) <= 253 and NAME.fullmatch(value) and ".." not in value


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _object(value):
    if not isinstance(value, dict) or value.get("apiVersion") != "v1" or value.get("kind") != "ConfigMap":
        raise IntentError("input must be a v1 ConfigMap object")
    meta = value.get("metadata", {})
    if not isinstance(meta, dict) or not _name(meta.get("name")) or not _name(meta.get("namespace")):
        raise IntentError("ConfigMap name and namespace are required")
    if meta.get("deletionTimestamp"):
        raise IntentError("deleting ConfigMaps cannot supply an intent")
    return meta


def _previous(value, namespace, name, owner):
    meta = _object(value)
    if (meta["namespace"] != namespace or meta["name"] != name
            or meta.get("labels", {}).get(OWNER) != owner):
        raise IntentError("previous intent belongs to another controller scope")
    data = value.get("data", {})
    if value.get("binaryData") or not isinstance(data, dict) or set(data) != {"intent.json"}:
        raise IntentError("previous intent has an invalid data envelope")
    try:
        intent = _json(data["intent.json"])
    except (ValueError, TypeError):
        raise IntentError("previous intent contains invalid JSON") from None
    if (not valid_lifecycle_intent(intent)
            or not isinstance(intent["bindings"], dict)
            or intent["bindings"].get("ownerID") != owner
            or intent["bindings"].get("namespace") != namespace):
        raise IntentError("previous intent has an invalid schema")
    reference = intent["profileRef"]
    if (not isinstance(reference, dict) or set(reference) not in ({"name", "uid", "sha256"}, {"name", "uid", "sha256", "planSHA256"})
            or ("planSHA256" in reference and not re.fullmatch(r"[0-9a-f]{64}", str(reference["planSHA256"])))
            or not _name(reference["name"]) or not _uuid(reference["uid"])
            or not isinstance(reference["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
        raise IntentError("previous profile reference is invalid")
    return intent


def build_intent(profile, bindings, *, name, generation, desired_state="Running", previous=None, pin_plan=False, restart_generation=None):
    """Validate locally and return the controller's exact ConfigMap envelope.

    Observed metadata is required, but a local file is not authenticated cluster
    evidence. The controller rechecks UID/hash/ownership against the live API.
    `previous` optionally detects generation mistakes before publication.
    """
    meta = _object(profile)
    if not _uuid(meta.get("uid")) or not isinstance(meta.get("resourceVersion"), str) or not meta["resourceVersion"]:
        raise IntentError("profile must include observed UID and resourceVersion")
    if not _name(name) or name == meta["name"]:
        raise IntentError("intent name must be valid and distinct from the profile")
    if type(generation) is not int or generation < 1 or desired_state not in {"Running", "Stopped"}:
        raise IntentError("a positive generation and Running or Stopped state are required")
    if (not isinstance(bindings, dict) or bindings.get("namespace") != meta["namespace"]
            or not _uuid(bindings.get("ownerID"))):
        raise IntentError("administrator namespace and canonical owner must match the profile scope")
    data = profile.get("data", {})
    if (profile.get("binaryData") or not isinstance(data, dict) or not data
            or any(not isinstance(k, str) or not KEY.fullmatch(k) or k in {".", ".."}
                   or not isinstance(v, str) for k, v in data.items())):
        raise IntentError("profile must contain string flat-file data only")
    if len(canonical(data).encode()) > MAX_DATA:
        raise IntentError("profile data exceeds the controller size bound")
    try:
        plan = compile_profile_files(data, bindings)
    except Exception:
        raise IntentError("profile or bindings are unsupported or invalid for this runtime") from None
    intent = {"schemaVersion": 1, "generation": generation, "desiredState": desired_state,
              "profileRef": {"name": meta["name"], "uid": meta["uid"], "sha256": digest(data)},
              "bindings": bindings}
    if pin_plan:
        intent["profileRef"]["planSHA256"] = plan["revision"]
    old = _previous(previous, meta["namespace"], name, bindings["ownerID"]) if previous is not None else None
    if restart_generation is None and old is not None:
        restart_generation = old.get("restartGeneration")
    if restart_generation is not None:
        intent["restartGeneration"] = restart_generation
    if not valid_lifecycle_intent(intent):
        raise IntentError("invalid restart generation")
    if old is not None:
        if intent.get("restartGeneration", 0) < old.get("restartGeneration", 0):
            raise IntentError("restart generation rolled back")
        if old["profileRef"]["name"] != meta["name"] or old["profileRef"]["uid"] != meta["uid"]:
            raise IntentError("profile identity changed; explicit controller recovery is required")
        if old["generation"] > generation or old["generation"] == generation and old != intent:
            raise IntentError("generation rolled back or was reused for different content")
    encoded = canonical(intent)
    if len(canonical({"intent.json": encoded}).encode()) > MAX_DATA:
        raise IntentError("intent data exceeds the controller size bound")
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": name, "namespace": meta["namespace"], "labels": {OWNER: bindings["ownerID"]}},
        "data": {"intent.json": encoded}}


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def _read(path, *, json_only=False):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise IntentError("local input exceeds the size bound")
        text = raw.decode("utf-8")
        return _json(text) if json_only else yaml.load(text, Loader=_UniqueSafeLoader)
    except IntentError:
        raise
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        raise IntentError("cannot parse the local input file") from None


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--profile-configmap", required=True, help="Observed ConfigMap JSON, including metadata UID/resourceVersion")
    parser.add_argument("--bindings", required=True, help="Administrator bindings YAML or JSON; no credential files are read")
    parser.add_argument("--name", required=True, help="Allowlisted controller intent ConfigMap name")
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--desired-state", choices=["Running", "Stopped"], default="Running")
    parser.add_argument("--restart-generation", type=int, help="Lifecycle restart generation; defaults to the previous value when updating")
    parser.add_argument("--pin-plan", action="store_true", help="Require the deployed compiler to produce exactly this plan before applying")
    parser.add_argument("--previous-intent", help="Optional existing intent ConfigMap JSON for update/generation checks")
    try:
        args = parser.parse_args(argv)
        result = build_intent(_read(args.profile_configmap, json_only=True), _read(args.bindings),
                              name=args.name, generation=args.generation, desired_state=args.desired_state, pin_plan=args.pin_plan, restart_generation=args.restart_generation,
                              previous=_read(args.previous_intent, json_only=True) if args.previous_intent else None)
        output = json.dumps(result, indent=2, sort_keys=True)
    except IntentError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("invalid controller intent inputs", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
