# VP CI tests

`test_ci.py` is the live VP test suite for this pattern. Install the `ci`
variant and explicitly set `TARGET_VARIANT=ci` when testing.

From the repository root, you can run the tests with:

```bash
export KUBECONFIG="${HOME}/.kube/config" # or the absolute path to your kubeconfig
VP_HUBCONFIG="$KUBECONFIG" TARGET_VARIANT=ci ./pattern.sh make run-ci-tests
```
