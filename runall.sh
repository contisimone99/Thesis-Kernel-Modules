#!/bin/sh 
set -e

sudo mount ./debian-rootfs/example.img -t ext4 /mnt/example
sudo find ./fx-module -name '*.ko' -exec cp "{}" /mnt/example/root  \;
sudo umount -t ext4 /mnt/example
sudo ~/qemu/build/qemu-system-x86_64 \
    -nographic \
    -device edu \
    -device fx \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 512M \
    -cpu host \
    -hda ./debian-rootfs/example.img \
    -k it \
    -s \
    -nographic \
    -netdev user,id=network0,hostfwd=tcp::10022-:22 -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
    -append "console=ttyS0 root=/dev/sda rw acpi=off nokaslr" \
    #-overcommit mem-lock=on \
    #2>stderror_file \
