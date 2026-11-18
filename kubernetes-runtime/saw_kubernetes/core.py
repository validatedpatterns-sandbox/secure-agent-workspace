"""Load the canonical shared SAW engine, never a module supplied by a profile.

The repository and controller image retain the same layout. The VM installer
embeds these source bytes in its signed bundle; both loaders use a content-keyed
module name so a process importing both frontends gets identical model classes.
"""

import hashlib
from pathlib import Path
import sys
import types


def load_shared(name):
    if name not in {"core", "admin"}:
        raise ValueError("unknown shared SAW source")
    source_path = (Path(__file__).resolve().parents[2] / "charts" / "openshell-saw"
                   / "files" / "installer" / ("saw_"+name+".py"))
    if source_path.is_symlink():
        raise RuntimeError("shared SAW core must be the trusted repository source file")
    source = source_path.read_bytes()
    module_name = "_saw_shared_"+name+"_" + hashlib.sha256(source).hexdigest()
    if module_name not in sys.modules:
        module = types.ModuleType(module_name)
        module.__file__ = str(source_path)
        sys.modules[module_name] = module
        try:
            exec(compile(source, str(source_path), "exec"), module.__dict__)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
    return sys.modules[module_name]


def load_core():
    return load_shared("core")


shared = load_core()
admin = load_shared("admin")
