# Build saw_spire.pp against the golden guest image policy baseline:
#   selinux-policy-43.3-1.fc44
#   selinux-policy-targeted-43.3-1.fc44
# Build-host package (never installed by the guest installer):
#   selinux-policy-devel-43.3-1.fc44
# plus checkpolicy, m4, make, and policycoreutils-devel.
#
# Those RPMs remain on the Fedora 44 release tree:
#   https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Everything/x86_64/os/Packages/s/
#
# Repeatable container build: ./build.sh
# Host build, only when the installed devel NVR is exactly the baseline:
#   make -C charts/openshell-saw/files/selinux
#
# Commit the generated saw_spire.pp.b64. The guest installer decodes it and
# runs semodule -i. It must not install selinux-policy-devel or compile policy.

BASELINE_NVR := 43.3-1.fc44

.PHONY: all check-baseline
all: saw_spire.pp

check-baseline:
	rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' selinux-policy-devel | grep -qx 'selinux-policy-devel-$(BASELINE_NVR)'
	rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' selinux-policy-targeted | grep -qx 'selinux-policy-targeted-$(BASELINE_NVR)'

saw_spire.pp: saw_spire.te saw_spire.fc check-baseline
	$(MAKE) -f /usr/share/selinux/devel/Makefile saw_spire.pp
