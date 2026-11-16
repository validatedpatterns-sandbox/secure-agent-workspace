# VM shutdown and restart

Use `make saw-restart OPENSHELL_SAW_NAME=<name>` to apply changed VM inputs. The
command uses the normal guest SSH access to run `sudo systemctl poweroff`, then
waits for a different Running VM instance. The chart's `runStrategy: Always`
starts that replacement with the updated mounted inputs and template. Check
`make saw-status` for the separate boot install/apply result before using agents.

This requires the same SSH key and guest access as `make saw-vm-ssh`. A stopped
or inaccessible guest cannot complete the restart; the command does not fall
back to forced host termination. SSH can disconnect with exit 255 as the guest
powers off. In that case the command still requires a different Running VM
instance before reporting success. Other SSH failures stop the command.
Non-Always run strategies are refused before requesting poweroff.
`RESTART_TIMEOUT` controls the replacement-instance wait (default 600 seconds).
`make saw-restart-pending CONFIRM=yes` uses this same path for each pending VM;
without confirmation it only lists the pending VMs.

## After a restart

A sandbox that still reports Error or Completed after the installer's 90-second
recovery grace is recreated with its `/sandbox` files and gateway password
carried over. The installer archives the workload volume and verifies the
archive before deleting anything. If archiving fails, nothing is deleted and
the apply reports the error. A pending restore resumes on the next apply.
Sandboxes held for confinement repair remain protected from recreation.

If a workload exits while the installer is waiting for exec after an upgrade,
the apply reports that startup failure and retries recovery on the next apply.
It leaves the existing tool policy intact. A startup failure detected before
checking confinement does not create a confinement-repair hold.

## If the guest is stuck without SSH

First try the VM console to shut down from inside the guest. If the guest
cannot be recovered, set `name` to the target VM's name and explicitly force a
restart only as a last resort:

```bash
virtctl restart "$name" -n "saw-$name" --force --grace-period=0
```

This abruptly stops the VM and can lose pending writes or damage its container
database. Preserve available disks, backups and evidence first; do not use it
on a VM whose data still needs recovery. The restart scripts never invoke this
fallback automatically. After recovery, check `make saw-status`, workspace
files and passwords, and container-database integrity before resuming work.
If `make saw-restart-pending CONFIRM=yes` stopped early, rerun it to process
the VMs still marked as waiting for restart.

## Why restart through the guest

During [#161](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/161),
the earlier `virtctl restart` implementation exceeded KubeVirt's implicit
30-second grace and force-terminated guests. Raising grace to 180 seconds alone
was insufficient: both controls again reached grace expiry and `Shutoff` reason
`Destroyed`. Their guest journals show shutdown had started and reached filesystem
unmounting; the exact component preventing completion remains unidentified.
Guest-initiated poweroff completed naturally on both controls in about a minute,
with filesystem sync/unmount and console power-down evidence. Avoid repeating
host-triggered restart as an operator recovery mechanism for these guests.

The chart also gives new VM instances a configurable 180-second termination
grace (`vm.terminationGracePeriodSeconds`, or
`defaults.openshellSaw.vm.terminationGracePeriodSeconds` for GitOps users). This
is an upper limit, not a fixed delay. It allows more time for other termination
paths, but is not a demonstrated fix for the host-triggered shutdown stall.

Updating a VM template does not update its current VMI's grace. After syncing
the template, `make saw-restart` performs the guest-poweroff transition and the
replacement adopts it. Verify both objects when checking that transition:

```bash
oc get vm "$name" -n "saw-$name" \
  -o jsonpath='{.spec.template.spec.terminationGracePeriodSeconds}{"\n"}'
oc get vmi "$name" -n "saw-$name" \
  -o jsonpath='{.spec.terminationGracePeriodSeconds}{"\n"}'
```

Capture the old guest's console and virtualization shutdown result when validating
restart. A new Running VMI or a non-force command alone does not prove completed
guest shutdown. Preserve existing disks and sandbox volumes.

One original VM had a damaged Podman SQLite catalog after restart; other VMs
retained healthy catalogs after forced teardown. The damaged VM had no
pre-restart integrity check. Its catalog damage's onset and cause remain
unproven. Neither the longer grace nor the restart command repairs that catalog.
