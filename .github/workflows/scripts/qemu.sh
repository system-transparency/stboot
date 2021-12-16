#!/usr/bin/env bash

set -Eeuo pipefail

LOG=/tmp/qemu.log
TIMEOUT=120
declare -a MATCH
# STBOOT banner
MATCH+=("  _____ _______   _____   ____   ____________")

cleanup () {
	qemu_pid=$(pgrep -f "qemu-system-x86_64.*")
	[ -z "$qemu_pid" ] || kill -TERM "${qemu_pid}"
	pkill -TERM -P $$
}

trap cleanup 0

# run qemu
qemu-system-x86_64 -nographic -kernel /boot/vmlinuz \
	-append "console=ttyS0,115200 uroot.uinitargs='-debug'" \
	-initrd out/initramfs.cpio -m 2048 </dev/null | tee /dev/stderr > "$LOG" &

i=0
while [ "$i" -lt "$TIMEOUT" ]
do
	for m in "${MATCH[@]}"
	do
		if grep -q "$m" "$LOG" >/dev/null 2>&1
		then
			echo "stboot banner reached. Test successful"
			exit 0
		fi
	done
	sleep 1
	i=$((i+1))
done

echo "TIMEOUT"
exit 1
