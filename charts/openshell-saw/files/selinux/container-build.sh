#!/bin/bash
# Runs inside the Fedora build container. Needs the 43.3 header files only.
set -eux
dnf install -y --setopt=install_weak_deps=False --exclude=selinux-policy* \
  checkpolicy m4 make policycoreutils-devel
mkdir -p /tmp/rpms
dnf download -y --destdir /tmp/rpms \
  selinux-policy-43.3-1.fc44 \
  selinux-policy-targeted-43.3-1.fc44 \
  selinux-policy-devel-43.3-1.fc44
# nodeps and noscripts: dependencies and scriptlets configure a running
# system. checkmodule only needs the header payload.
rpm -Uvh --nodeps --noscripts --oldpackage \
  /tmp/rpms/selinux-policy-43.3-1.fc44*.rpm \
  /tmp/rpms/selinux-policy-targeted-43.3-1.fc44*.rpm \
  /tmp/rpms/selinux-policy-devel-43.3-1.fc44*.rpm
rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' selinux-policy selinux-policy-targeted selinux-policy-devel
mkdir -p /etc/selinux
printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' > /etc/selinux/config
make
rm -rf tmp saw_spire.if
