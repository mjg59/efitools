#!/bin/sh
k=$1
e=$2
o=$3
if [ $# -ne 3 ]; then
    echo "Usage $0: key_dir efi_dir output_image_file"
    exit 1;
fi
t=/var/tmp/tmpusb.$$.img
if [ ! -d "$k" ]; then
    echo "Failed to find directory $k"
    exit 1;
fi
if [ ! -d "$e" ]; then
    echo "Failed to find directory $e"
    exit 1;
fi

dd if=/dev/zero of=${o} bs=512 count=102096
parted ${o} "mktable gpt"
parted ${o} "mkpart p fat32 2048s 102049s"
parted ${o} "toggle 1 boot"
parted ${o} "name 1 UEFI"
dd if=/dev/zero of=${t} bs=512 count=100000
mkfs -t vfat -n UEFI-Tools ${t}
mmd -i ${t} ::/EFI
mmd -i ${t} ::/EFI/BOOT
mmd -i ${t} ::/keys
mcopy -i ${t} ${k}/*.esl ::/keys
mcopy -i ${t} ${k}/*.auth ::/keys
mcopy -i ${t} ${e}/HashTool-signed.efi ::/EFI/BOOT/HashTool.efi
mcopy -i ${t} ${e}/KeyTool-signed.efi ::/EFI/BOOT/KeyTool.efi
mcopy -i ${t} ${e}/PreLoader-signed.efi ::/EFI/BOOT/BOOTX64.efi
mcopy -i ${t} ${e}/HelloWorld.efi ::/EFI/BOOT/loader.efi
dd if=${t} of=${o} bs=512 seek=2048 count=100000
rm -f ${t}
exit 0;
