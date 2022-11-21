# stboot

The reference bootloader implementation for System Transparency.

# Description
The stboot bootloader can be used as an init program inside an initramfs and is designed to be combined with a Linux kernel to form a [LinuxBoot](https://www.linuxboot.org/) distribution. It is closely related to the [u-root project](https://github.com/u-root/u-root#u-root). On the one hand, stboot depends on some standard Linux tools packages provided by u-root, on the other hand, u-root is used to create an initramfs including stboot.

# Usage
Make sure your Go version is >=1.13 && <1.16. Make sure your GOPATH is set up correctly. Although using modules, stboot still vendors dependencies to work smoothly with u-root. So if you are usually working with go modules enabled do the following in your working directory:

```
mkdir go
export GO111MODULE=off
export GOPATH=${PWD}/go
```

Download and install u-root and stboot:
```
go get github.com/u-root/u-root
go get github.com/system-transparency/stboot
```

Build an initramfs:
```
./go/bin/u-root -o initramfs.cpio -uinitcmd stboot github.com/u-root/u-root/cmds/core/{init,elvish,ls} github.com/system-transparency/stboot
```
There should be your brand new `initramfs.cpio` in you working directory.

Test your initramfs (assuming your OS kernel at `/boot/vmlinuz`):
```
qemu-system-x86_64 -kernel /boot/vmlinuz -nographic -append "console=ttyS0,115200 uroot.uinitargs='-debug'" -initrd initramfs.cpio -m 2048 --enable-kvm
```

You should see something like this:
```
[...]
[    0.689686] Run /init as init process
2021/05/03 12:01:15 Welcome to u-root!
                              _
   _   _      _ __ ___   ___ | |_
  | | | |____| '__/ _ \ / _ \| __|
  | |_| |____| | | (_) | (_) | |_
   \__,_|    |_|  \___/ \___/ \__|

init: 2021/05/03 12:01:15 no modules found matching '/lib/modules/*.ko'
stboot: 
  _____ _______   _____   ____   ____________
 / ____|__   __|  |  _ \ / __ \ / __ \__   __|
| (___    | |     | |_) | |  | | |  | | | |   
 \___ \   | |     |  _ <| |  | | |  | | | |   
 ____) |  | |     | |_) | |__| | |__| | | |   
|_____/   |_|     |____/ \____/ \____/  |_|   

recovery: load security config: read file: open /etc/security_configuration.json: no such file or directory
```
As long as you can see the stboot banner, everything is fine. The program will exit with an error because of missing configuration data.
See https://github.com/system-transparency/system-transparency for details on how to set up System Transparency.
