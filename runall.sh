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
    -m 512M,maxmem=1G \
    -cpu host \
    -drive file=./debian-rootfs/example.img,format=raw,media=disk,if=ide \
    -k it \
    -s \
    -netdev user,id=network0,hostfwd=tcp::10022-:22 \
    -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
    -object memory-backend-ram,id=vaultmem,size=64M \
    -device virtio-mem-pci,id=vault0,memdev=vaultmem,memaddr=0x100000000,requested-size=0,block-size=2M \
    -append "console=ttyS0 root=/dev/sda rw acpi=off nokaslr" \
    #2>/tmp/qemu-kvm.log
