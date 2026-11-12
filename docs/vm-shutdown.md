# VM shutdown and restart

The SAW chart gives each new VM instance 180 seconds to complete guest shutdown
before KubeVirt force-terminates it. Configure this with
`vm.terminationGracePeriodSeconds` in the SAW values, or
`defaults.openshellSaw.vm.terminationGracePeriodSeconds` for GitOps users. A VM
that shuts down sooner restarts sooner; this is an upper limit, not a fixed delay.

The Fedora guest's service stop timeout is 45 seconds. During the acceptance
investigation in [#161](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/161),
both original VMs exceeded KubeVirt's implicit 30-second grace period during a
normal `make saw-restart`. Virtualization logs recorded `Grace period expired`
and `Shutoff` with reason `Destroyed`. Giving the guest time to finish its
shutdown also gives it time to sync its filesystems.

One of those VMs had a damaged Podman SQLite catalog after restart; the other
retained a healthy catalog. The damaged VM had no pre-restart integrity check.
The forced shutdowns are confirmed, but the catalog damage's cause and onset
remain unproven. The longer grace is not a database repair or a demonstrated
fix for that catalog's corruption.

## Existing VM instances

Updating a VM template does not update the grace period of its currently running
VMI. Verify both objects before the first transition:

```bash
oc get vm "$name" -n "saw-$name" \
  -o jsonpath='{.spec.template.spec.terminationGracePeriodSeconds}{"\n"}'
oc get vmi "$name" -n "saw-$name" \
  -o jsonpath='{.spec.terminationGracePeriodSeconds}{"\n"}'
```

For an instance still using the old short/implicit grace, first sync the updated
VM template. Then enter the guest with `make saw-vm-ssh OPENSHELL_SAW_NAME=<name>`
and run `sudo systemctl poweroff`. The chart's `runStrategy: Always` starts a new
instance after the guest finishes powering off. This transition lets the guest
finish before any host-requested termination timer starts. Verify the new VMI
has the configured grace period and boot install/apply finish before further
validation. Preserve existing disks and sandbox volumes during the transition.

For subsequent restarts, use the documented
`make saw-restart OPENSHELL_SAW_NAME=<name>` and observe the shutdown result.
Do not count a non-force command or a newly Ready VMI as proof of graceful
shutdown: capture the old guest's console and virtualization logs and confirm
no grace expiry/forced teardown occurred. If shutdown still exceeds the configured
limit, investigate the blocked guest services and choose a limit appropriate to
that workload.
