import os
import sys

# Make sibling helper modules (e.g. quickstart_scripts) importable from the test
# modules regardless of pytest's working directory / invocation path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from validatedpatterns_tests.interop.conftest_openshift import *  # noqa: E402,F401,F403
