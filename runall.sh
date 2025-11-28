#!/bin/sh
set -e

MNT=/mnt/example
IMG=./debian-rootfs/example.img

# Crea il mount point se non esiste
sudo mkdir -p "$MNT"

# Monta l'immagine
sudo mount -o loop -t ext4 "$IMG" "$MNT"

# Copia i .ko dentro /root dell'FS
sudo find ./fx-module -name '*.ko' -exec cp "{}" "$MNT/root" \;

sudo umount "$MNT"

# Avvia QEMU
sudo ~/qemu/build/qemu-system-x86_64 \
    -nographic \
    -device edu \
    -device fx \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 512M \
    -cpu host \
    -drive file=./debian-rootfs/example.img,format=raw,media=disk,if=ide \
    -k it \
    -s \
    -netdev user,id=network0,hostfwd=tcp::10022-:22 \
    -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
    -append "console=ttyS0 root=/dev/sda rw acpi=off nokaslr"
    #-overcommit mem-lock=on \
    #2>stderror_file \