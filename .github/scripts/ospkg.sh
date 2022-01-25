#!/bin/sh

dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)
root="$(cd "${dir}/../../" && pwd)"

set -eux

out="$root/out"
keys="$out/keys"
ospkg_dir="$out/ospkg"
key_num="5"
kernel="$out/ubuntu-focal-amd64.vmlinuz"
initrd="$out/ubuntu-focal-amd64.cpio.gz"
cmd="console=tty0 console=ttyS0,115200n8 rw rdinit=/lib/systemd/systemd"
ospkg="os-pkg-example-ubuntu20.zip"

export PATH="$GOPATH/bin:$PATH"
export GO111MODULE="off"

mkdir -p "$keys" "$ospkg_dir"

# Self-sign root certificate
stmgr keygen certificate -isCA -certOut="$keys/root.cert" -keyOut="$keys/root.key"

# Signing keys
for i in $(seq 1 $key_num)
do
    stmgr keygen certificate -rootCert="$keys/root.cert" -rootKey="$keys/root.key" -certOut="$keys/signing-key-$i.cert" -keyOut="$keys/signing-key-$i.key"
done

# Create ospkg
stmgr ospkg create -out "$ospkg_dir/$ospkg" -kernel="$kernel" -initramfs="$initrd" -cmdline="$cmd" -url="http://10.0.2.2:8080/$ospkg"
for i in $(seq 1 $key_num)
do
	stmgr ospkg sign -key="$keys/signing-key-$i.key" -cert="$keys/signing-key-$i.cert" -ospkg="$ospkg_dir/$ospkg"
done
