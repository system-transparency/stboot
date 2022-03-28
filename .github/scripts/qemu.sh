#!/usr/bin/env bash

dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)
root="$(cd "$dir/../../" && pwd)"
out="$root/out"
ospkg_dir="$out/ospkg"

set -Eeuo pipefail

LOG=/tmp/qemu.log
python_http_server="python3 -m http.server 8080"
TIMEOUT=
mode="${1:-vanilla}"
declare -a MATCH
# STBOOT banner

case "$mode" in
	vanilla)
		TIMEOUT=120
		MATCH+=("  _____ _______   _____   ____   ____________")
		;;
	complete)
		TIMEOUT=300
		#Ubuntu Focal
		MATCH+=("Ubuntu 20.04 LTS ubuntu ttyS0")
		#Ubuntu Bionic
		MATCH+=("Ubuntu 18.04 LTS ubuntu ttyS0")
		#Debian Buster
		MATCH+=("Debian GNU/Linux 10 debian ttyS0")
		# start python web server
		(cd $ospkg_dir && $python_http_server) &
		;;
	*)
		>2& echo "Mode $mode not found!"
		exit2
		;;
esac

cleanup () {
	qemu_pid=$(pgrep -f "qemu-system-x86_64.*")
	[ -z "$qemu_pid" ] || kill -TERM "${qemu_pid}"
	pkill -TERM -P $$
}

trap cleanup 0

# run qemu
qemu-system-x86_64 -nographic -kernel "$root/.github/assets/vmlinuz" \
	-M q35 \
	-m "4G" \
	-net user \
	-net nic \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-pci,rng=rng0 \
	-rtc base=localtime \
	-nographic \
	-append "console=ttyS0,115200 uroot.uinitargs=\"-loglevel=d\"" \
	-initrd $out/initramfs.cpio </dev/null | tee /dev/stderr > "$LOG" &

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
