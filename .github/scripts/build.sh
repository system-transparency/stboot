#!/bin/sh

dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)
root="$(cd "$dir/../../" && pwd)"

set -eux

export PATH="$GOPATH/bin:$PATH"
export GO111MODULE="off"

out="$root/out"

initrd="$out/initramfs.cpio"
signing_root="$out/keys/root.cert"
timestamp_file="$out/system_time_fix"

date +%s > "$timestamp_file"

u-root -build=bb -uinitcmd=stboot -defaultsh="" -o "${initrd}" \
	-files "$root/.github/assets/security_configuration.json:etc/security_configuration.json" \
	-files "$root/.github/assets/host_configuration.json:etc/host_configuration.json" \
	-files "$root/.github/assets/https_roots.pem:etc/https_roots.pem" \
	-files "$signing_root:etc/ospkg_signing_root.pem" \
	-files "$timestamp_file:etc/system_time_fix" \
	-files "/lib/modules/$(uname -r)/kernel/drivers/virtio:/lib/modules/" \
	github.com/u-root/u-root/cmds/core/init \
	github.com/system-transparency/stboot
