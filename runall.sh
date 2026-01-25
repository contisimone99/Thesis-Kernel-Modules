#!/bin/sh
set -e

MNT=/mnt/example
IMG=./debian-rootfs/example.img

# Create mount point
sudo mkdir -p "$MNT"

# Mount image
sudo mount -o loop -t ext4 "$IMG" "$MNT"

# Copy .ko files into /root of the FS
sudo find ./fx-module -name '*.ko' -exec cp "{}" "$MNT/root" \;

# copy one shot boot script
sudo cp ./fx-boot.sh "$MNT/root/fx-boot.sh"
sudo chmod 0700 "$MNT/root/fx-boot.sh"
sudo chown root:root "$MNT/root/fx-boot.sh"

# 3) Scrivi la unit systemd nel guest
sudo mkdir -p "$MNT/etc/systemd/system"
sudo tee "$MNT/etc/systemd/system/fx-boot.service" >/dev/null <<'EOF'
[Unit]
Description=FX one-shot bootstrap (load module, cleanup, self-remove)
DefaultDependencies=yes
Wants=network-online.target
After=network-online.target ssh.service

[Service]
Type=oneshot
ExecStart=/root/fx-boot.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF

sudo chmod 0644 "$MNT/etc/systemd/system/fx-boot.service"
sudo chown root:root "$MNT/etc/systemd/system/fx-boot.service"

# 4) Enable offline: symlink in multi-user.target.wants
sudo mkdir -p "$MNT/etc/systemd/system/multi-user.target.wants"
sudo ln -sf ../fx-boot.service \
  "$MNT/etc/systemd/system/multi-user.target.wants/fx-boot.service"

sudo umount "$MNT"


sudo ~/qemu/build/qemu-system-x86_64 \
    -nographic \
    -device edu \
    -device fx \
    -enable-kvm \
    -kernel ./bzImage \
    -boot c \
    -m 512M,maxmem=1G \
    -cpu host \
    -smp 4 \
    -drive file=./debian-rootfs/example.img,format=raw,media=disk,if=ide \
    -k it \
    -s \
    -netdev user,id=network0,hostfwd=tcp::10022-:22 \
    -device e1000,netdev=network0,mac=52:54:00:12:34:56 \
    -append "console=ttyS0 root=/dev/sda rw" \
    2>/tmp/qemu-kvm.log

#