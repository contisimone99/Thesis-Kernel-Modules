# 1. Creazione directory se non esiste
mkdir -p debian-rootfs
cd debian-rootfs

# 2. Creazione dell'immagine 4GB
qemu-img create example.img 4G

# 3. Formattazione in ext4
sudo mkfs.ext4 example.img

# 4. Montaggio dell'immagine
sudo mount example.img /mnt

# 5. Installazione Debian minimale all'interno dell'immagine
sudo debootstrap --arch=amd64 stable /mnt http://deb.debian.org/debian/

# 6. Configurazione fstab
echo "/dev/sda / ext4 defaults 0 1" | sudo tee /mnt/etc/fstab

# 7. Impostazione password root ("root")
echo "root:root" | sudo chroot /mnt chpasswd

# 8. Configurazioni rete di base
sudo bash -c 'echo "auto lo" > /mnt/etc/network/interfaces'
sudo bash -c 'echo "iface lo inet loopback" >> /mnt/etc/network/interfaces'

# 9. Installazione SSH
sudo chroot /mnt apt update
sudo chroot /mnt apt install -y openssh-server

# 10. Abilitazione SSH al boot
sudo chroot /mnt systemctl enable ssh

# 11. Pulizia cache apt
sudo chroot /mnt apt clean

# 12. Smontaggio
sudo umount /mnt
