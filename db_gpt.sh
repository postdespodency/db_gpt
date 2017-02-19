#!/bin/bash
#
# Debootstrap script for fully encrypted Debian 8 installation, pre-boot authentication. 
# 
# (c) 2016 David Gressel
# http://dckg.net
#
# It installs an optionally encrypted, minimal debian system, based on LVM and GPT.
# The installation process is fully automatic and unattended.
# Install time: 50 Mbit/s link, HDD, 1GB RAM, 4x3,4Ghz Intel Xeon: <= 5 minutes. :)
# 
# Script won't do any cleanup. If you have active RAID or PVs, it will fail. 
# 
# Debian installation is done from within a Debian-Environment itself.
# System will first be installed into RAM, configured, and is then copied to drive.
#
# Modify to your requirements in [USER CONFIGURATION] below.
# Script has to be run as root.
# Execute as ./script.sh - piping in bash does not work!
#
# You might want to run
# apt-get install kbd # to setup keyboard-layout
# dpkg-reconfigure tzdata # to set timezone
# dpkg-reconfigure locales # to set language different than english
# lvresize --resizefs --size 12345G /dev/mapper/vg0-root to increase rootfs space
# later.
#
# Initial root password is root.
#
# Important Notice For RAID
# Raid is only used for data partition. /boot, EFI-Boot-Partition, BIOS-Boot-Partition are not duplicated!
# That means, if primary DRIVE fails, you might loose the ability to reboot until you recreate these partitons, reinstall initramfs & bootloader...
# AFAIK ATM it is not possible to use RAID for EFI/boot partiton.
# After first reboot (after installation with live image), mdadm does a resync. This is normal.
# 
# Bugs / Feedback / Contribute
# Bugreports / feedback like working configurations are greatly appreciated.
# Contributions are welcome. 
#  
# License (GPL v3): 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#
ABSOLUTE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# [USER CONFIGURATION]
DRIVE=sda # target drive, where to install system. ALL DATA WILL BE LOST!
CRYPTO=0 # create encrypted lvm + dropbear for pre boot authentication, - will ask for password after debootstrap
ROOTFS_SIZE="1G" # lvm compatible notation
SUITE=jessie
DEBIAN_VERSION=8 # int, needed for release signature files
#DEBIAN_MIRROR="http://mirrors.online.net/debian" # will only work from within online.net's network
#DEBIAN_MIRROR="http://ftp.de.debian.org/debian"
DEBIAN_MIRROR="http://mirror.1und1.de/debian" # Located in Karlsruhe / Germany, 2Gbit/s
# ARCH = amd64, has to be changed manually (Ctrl+F ...)

# RAID Config
SETUP_RAID=0 # 1 true, 0 false, setup RAID
DRIVE_RAID=sdb # second drive for RAID
RAID_LEVEL=mirror # mirror (RAID 1) or stripe (RAID 0), see mdadm man page
# [USER CONFIGURATION END]

# Tested Configurations (= successful boot after script was run), using grml live linux from 2014
# jessie
# crypto 0, BIOS
# crypto 0, EFI
# crypto 1, BIOS ( Ubuntu 14.xx live cd, grml )
# crypto 1, EFI
# crypto 0, raid 1, BIOS
# crypto 1, raid 1, BIOS
#


ROOTFS_DEV=${DRIVE}4


DEFAULT_COLOR="\x1b[0m"
CYAN="\x1b[36;01m"
GREEN="\x1b[32;01m"
YELLOW="\x1b[33;01m"
RED="\x1b[31;01m"


function debug () {
    echo -e $CYAN$1$DEFAULT_COLOR
}

function info () {
    echo -e $GREEN$1$DEFAULT_COLOR
}

function warn () {
    echo -e $YELLOW$1$DEFAULT_COLOR
}

function die () {
    error "FAILURE! EXITING SCRIPT NOW!"
    exit
}

function error () {
    echo -e $RED$1$DEFAULT_COLOR
}

function partition_lvm () {
    debug "partition_lvm: $1"
    lvcreate -n root -L $ROOTFS_SIZE vg0 --verbose || die

    mkfs.ext4 /dev/vg0/root || die
    mount /dev/vg0/root /mnt/chroot || die
    debug lvs
    lvs
}

function prepare_lvm () {
    debug "prepare_lvm: $1"
    pvcreate $1 || die
    vgcreate vg0 $1 || die
    pvscan
    vgscan
    lvscan
    debug lvs
    lvs
}

function setup_lvm () {
    debug "setup_lvm: $1"
    service udev restart
    partprobe
    prepare_lvm $1
    partition_lvm $1
    debug "setup lvm done"
}

function set_user_password () {
    echo -e "$1\n$2" | (passwd $1)
    debug "password of user $1 changed to $2"
}

function set_sshd_settings () {
    # disable password authentication
    sed -i 's|[#]*PasswordAuthentication yes|PasswordAuthentication no|g' /etc/ssh/sshd_config
}

function setup_zsh () {
    wget -qO /etc/zsh/zshrc http://git.grml.org/f/grml-etc-core/etc/zsh/zshrc
    echo "export EDITOR=nano" >> /etc/zsh/zshrc
    chsh -s /bin/zsh; cp /etc/zsh/zshrc ~/.zshrc
}

function finalize_chroot () {
    set_user_password root root
    set_sshd_settings
    setup_zsh
    rm /root/script.sh
    rm /root/ischroot
}

export -f finalize_chroot
export -f set_user_password
export -f set_sshd_settings
export -f setup_zsh
export -f debug

info "Welcome! Sit back; don't relax yet..."
debug "script path: $ABSOLUTE_PATH"

#  ____   _    ____ _____   _ 
# |  _ \ / \  |  _ \_   _| / |
# | |_) / _ \ | |_) || |   | |
# |  __/ ___ \|  _ < | |   | |
# |_| /_/   \_\_| \_\|_|   |_|
#                             
# install debian system to ramdisk
# for chrooting into it and doing the real work from within there in PART 2
#
if [ ! -e /root/ischroot ]; then

    warn "[PART 1]"
    cd ~
    mkdir -p /mnt/chroot/
    mkdir temp-ramdisk
    chmod 700 temp-ramdisk
    mount -t tmpfs -o size=2g tmpfs temp-ramdisk || die

    cd temp-ramdisk

    # install debootstrap from upstream
    info "[INSTALL DEBOOTSTRAP]"
    wget -q --wait=0.1 -m -np http://ftp.debian.org/debian/pool/main/d/debootstrap/
    DEBOOTSTRAP=$(find . -iname "debootstrap_*_all.deb" | grep -v "+" | grep -v "~" | head -n1)
    mv $DEBOOTSTRAP debootstrap_all.deb || die
    ar -x debootstrap_all.deb
    tar xf data.tar.gz -C /

    wget -q https://ftp-master.debian.org/keys/archive-key-${DEBIAN_VERSION}.asc -O key.asc
    gpg --keyring=debootstrap.gpg --no-default-keyring --import key.asc

    wget -q https://ftp-master.debian.org/keys/archive-key-${DEBIAN_VERSION}-security.asc -O key.asc
    gpg --keyring=debootstrap.gpg --no-default-keyring --import key.asc


    info "[INSTALL DEBIAN ${DEBIAN_VERSION}: $SUITE TO RAMDISK]"
    debootstrap --keyring=debootstrap.gpg --arch=amd64 --include=debian-archive-keyring,nano,zsh,locales,ca-certificates,wget,lvm2,cryptsetup,parted,gdisk,rsync,mdadm,dosfstools,linux-image-amd64,ntp,grub2,openssh-server $SUITE rootfs-debian $DEBIAN_MIRROR | tee debootstrap.log || die

    grep -q "Valid Release signature" debootstrap.log
    if [ $? -ne 0 ]; then
        error "debootstrap failed / release signatures not validated"
        die
    fi;
    cd rootfs-debian
    mkdir parentroot
    chmod 700 parentroot
    for dir in dev proc sys mnt; do mount --bind /$dir $dir; done
    mount --bind / parentroot
    touch root/ischroot
    cp $ABSOLUTE_PATH root/script.sh
    chmod +x script.sh

    chroot . /bin/bash -c "su -c 'apt-get clean'"
    echo "# Security updates
deb http://security.debian.org/ $SUITE/updates main contrib non-free
#deb-src http://security.debian.org/ $SUITE/updates main contrib non-free

## Debian mirror

# Base repository
deb $DEBIAN_MIRROR $SUITE main contrib non-free
#deb-src $DEBIAN_MIRROR $SUITE main contrib non-free

# Stable updates
deb $DEBIAN_MIRROR $SUITE-updates main contrib non-free
#deb-src $DEBIAN_MIRROR $SUITE-updates main contrib non-free

# Stable backports
deb $DEBIAN_MIRROR $SUITE-backports main contrib non-free
#deb-src $DEBIAN_MIRROR $SUITE-backports main contrib non-free" > etc/apt/sources.list

    echo "# allow installed backports to receive updates
Package: *
Pin: release a=$SUITE-backports
Pin-Priority: 200" > etc/apt/preferences

    chroot . /bin/bash -c "su -c 'apt-get update'"
    cp /etc/network/interfaces etc/network/interfaces # copy host network configuration into new system

    if modprobe efivars; then # returns wrong value in chroot
        touch ./tmp/is_efi
    fi
    debug "CHROOTING INTO RAMDISK SYSTEM!"
    chroot . /bin/bash -c "su -c '/root/script.sh | tee -a /tmp/install.log'"

    exit
    cd -
fi;
#echo 3 > /proc/sys/vm/drop_caches 

# ____   _    ____ _____   ____  
# |  _ \ / \  |  _ \_   _| |___ \ 
# | |_) / _ \ | |_) || |     __) |
# |  __/ ___ \|  _ < | |    / __/ 
# |_| /_/   \_\_| \_\|_|   |_____|
#                                 
#
# runs from debian environment installed to ramdisk
# installs itself to disk *_*
#

warn "[PART 2]"
info "[PARTITIONING DRIVE]"
sgdisk -Z /dev/${DRIVE} || die # zero previous partition table
sgdisk -og /dev/${DRIVE} || die
sgdisk -n 1:2048:4095 -c 1:"BIOS Boot Partition" -t 1:ef02 /dev/${DRIVE} || die # 1M
sgdisk -n 2:4096:413695 -c 2:"EFI System Partition" -t 2:ef00 /dev/${DRIVE} || die # 200M
sgdisk -n 3:413696:1028095 -c 3:"Linux /boot" -t 3:8300 /dev/${DRIVE} || die # 300M
ENDSECTOR=$(sgdisk -E /dev/{DRIVE})
if [ $SETUP_RAID == 0 ]; then
    if [ $CRYPTO == 0 ]; then # just for convenience...
        sgdisk -n 4:1028096:$ENDSECTOR -c 4:"Linux LVM" -t 4:8e00 /dev/${DRIVE} || die
    else
        sgdisk -n 4:1028096:$ENDSECTOR -c 4:"Linux dm-crypt" -t 4:8300 /dev/${DRIVE} || die
    fi
else
    sgdisk -n 4:1028096:$ENDSECTOR -c 4:"Linux RAID $RAID_LEVEL" -t 4:fd00 /dev/${DRIVE} || die
fi;
sgdisk --print /dev/${DRIVE} || die


if [ $SETUP_RAID == 1 ]; then # copy partition table to second drive
    info "[SETUP RAID]"
    sgdisk -R /dev/$DRIVE_RAID /dev/$DRIVE || die
    sgdisk -G /dev/$DRIVE_RAID || die
    partprobe
    echo y | mdadm --create --verbose /dev/md0 --level=$RAID_LEVEL --raid-devices=2 /dev/${DRIVE}4 /dev/${DRIVE_RAID}4 || die
    ROOTFS_DEV=md0
fi;


if [ $CRYPTO == 0 ]; then
    info "[SETUP LVM]"
    setup_lvm /dev/$ROOTFS_DEV
else
    info "[SETUP ENCRYPTION]"

    info  "Luks Format, enter passphrase..."
    read -rp "enter passphrase and hit [enter]" pass
    info "pass: $pass";
    echo -n $pass | cryptsetup luksFormat -c aes-xts-plain64 -s 512 -h sha512 -i 2000 /dev/$ROOTFS_DEV -
    echo -n $pass | cryptsetup luksOpen /dev/$ROOTFS_DEV ${ROOTFS_DEV}_crypt -d -
    pass=0
    info "[SETUP LVM]"
    setup_lvm /dev/mapper/${ROOTFS_DEV}_crypt
fi


export DEBIAN_FRONTEND=noninteractive;
cd /mnt/chroot
info "[FORMATTING PARTITIONS]"
mkfs.ext4 -O ^has_journal -F /dev/${DRIVE}3 || die
mkdir boot
debug "mount boot"
mount /dev/${DRIVE}3 boot || die

mkdosfs -F 32 -I /dev/${DRIVE}2 || die # EFI partition

if [ $SETUP_RAID == 1 ]; then
    mkfs.ext4 -O ^has_journal -F /dev/${DRIVE_RAID}3 || die
    mkdosfs -F 32 -I /dev/${DRIVE_RAID}2 || die # EFI partition
fi;

info "[RSYNC DEBIAN ${DEBIAN_VERSION}: $SUITE TO DRIVE]"
rsync -aAX --info=progress2 --exclude={"/parentroot","/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} / /mnt/chroot/ || die
sync

info "[CHROOT INTO THE SYSTEM]"
for dir in dev proc sys mnt; do mount --bind /$dir $dir; done
echo "UUID=$(blkid -s UUID -o value /dev/${DRIVE}3) /boot ext4 defaults 0 2" > etc/fstab;
if [ -e /tmp/is_efi ]; then
    echo "UUID=$(blkid -s UUID -o value /dev/${DRIVE}2) /boot/efi vfat defaults 0 2" >> etc/fstab;
fi

chroot . /bin/bash -c "su -c 'mkdir -p /root/.ssh'"
chroot . /bin/bash -c "su -c 'touch /root/.ssh/authorized_keys'"

chroot . /bin/bash -c "su -c 'locale-gen \"C.UTF-8\"'"
chroot . /bin/bash -c "su -c 'echo LANG=\"C.UTF-8\" > /etc/default/locale'"

if [ $CRYPTO == 0 ]; then
    echo "/dev/mapper/vg0-root / ext4 defaults,errors=remount-ro 0 1" >> etc/fstab;
else
    echo "${ROOTFS_DEV}_crypt UUID=$(blkid -s UUID -o value /dev/$ROOTFS_DEV) none luks" >> etc/crypttab;
    echo "/dev/mapper/vg0-root / ext4 defaults,errors=remount-ro 0 1" >> etc/fstab;
fi

if [ $CRYPTO == 1 ]; then
    chroot . /bin/bash -c "su -c 'apt-get install initramfs-tools busybox dropbear -y;'"
    chroot . /bin/bash -c "su -c 'echo \"DEVICE=eth0\" >> /etc/initramfs-tools/initramfs.conf'"
    #
    # Pre-boot IP configuration, consult the kernel docs for more info: 
    # https://www.kernel.org/doc/Documentation/filesystems/nfs/nfsroot.txt
    # Ctrl+F
    # ip=dhcp
    #
    # static ip
    # ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>:
    # ip=192.168.123.123::192.168.123.1:255.255.255.0::eth0:none
    chroot . /bin/bash -c "su -c 'echo \"export IP=dhcp\" >> /etc/initramfs-tools/initramfs.conf'"

    NETWORK_CARD_DRIVER=$(cat /sys/class/net/eth0/device/uevent | grep DRIVER | awk '{print substr($0,8)}')
    debug "NETWORK_CARD_DRIVER: $NETWORK_CARD_DRIVER"
    echo $NETWORK_CARD_DRIVER >> etc/initramfs-tools/modules
    # chroot . /bin/bash -c "su -c 'echo GRUB_ENABLE_CRYPTODISK=y >> /etc/default/grub'" # only if encrypted /boot is used, which is never the case here; can make grub stuck on boot
    chroot . /bin/bash -c "su -c 'update-rc.d dropbear disable'" # disable dropbear in real system => we want normal openssh-server after unlocking
    chroot . /bin/bash -c "su-c 'update-initramfs -u -k all'"
    cat etc/initramfs-tools/root/.ssh/id_rsa | tee > root/.ssh/id_rsa_dropbear
    chroot . /bin/bash -c "su -c 'chmod 400 ~/.ssh/id_rsa_dropbear'"
    chroot . /bin/bash -c "su -c 'ssh-keygen -yf ~/.ssh/id_rsa_dropbear > ~/.ssh/id_rsa_dropbear.pub'"
    chroot . /bin/bash -c "su -c 'ssh-keygen -lf ~/.ssh/id_rsa_dropbear.pub >> ~/ssh_localhost_fingerprints'"
    
    info "dropbear private key, written to /root/temp-ramdisk/rootfs-debian/mnt/chroot/root/.ssh/id_rsa_dropbear"
    debug "initramfs modules"
    cat etc/initramfs-tools/modules
fi
chroot . /bin/bash -c "su -c 'find etc/ssh/ -name \*.pub -type f -exec  ssh-keygen -lf {} \; >> ~/ssh_localhost_fingerprints'"

#service udev restart
info "[INSTALL BOOTLOADER]"
if [ -e /tmp/is_efi ]; then
    info "[INSTALL EFI BOOTLOADER]"
    chroot . /bin/bash -c "su -c 'mkdir -p /boot/efi'"
    chroot . /bin/bash -c "su -c 'mount /dev/${DRIVE}2 /boot/efi'"
    chroot . /bin/bash -c "su -c 'apt-get -y install --reinstall grub-efi'"
    chroot . /bin/bash -c "su -c 'grub-install --efi-directory=/boot/efi /dev/${DRIVE}; update-grub'"
    if [ ! -e boot/efi/EFI/debian/grubx64.efi ]; then
        error "installing UEFI Bootloader possibly failed"
        die
    fi;
    debug "efibootmgr output"
    chroot . /bin/bash -c "su -c 'efibootmgr --verbose'"
else
    chroot . /bin/bash -c "su -c 'grub-install /dev/${DRIVE}; update-grub'"
fi

chroot . /bin/bash -c "su -c 'finalize_chroot'"
info "[EXIT CHROOT]"
debug [FILESYSTEM INFO]
gdisk -l /dev/${DRIVE}
lsblk
debug fstab
cat etc/fstab
debug crypttab
cat etc/crypttab
sync
info "DONE!"
warn "Dont forget to copy your sshkey into /root/temp-ramdisk/rootfs-debian/mnt/chroot/root/.ssh/authorized_keys & (download dropbear private key, saved in /root/temp-ramdisk/rootfs-debian/mnt/chroot/root/.ssh/id_rsa_dropbear)"
info "fingerprints"
cat root/ssh_localhost_fingerprints
#
# unlock system later:
# echo -n "pwd" > /lib/cryptsetup/passfifo
# root password: root
