

.DEFAULT_GOAL := all


.PHONY: make-disk-img
make-disk-img:
	mkdir -p ./run-ovmf/fs-mnt/
	dd if=/dev/zero of=run-ovmf/disk.img bs=1M count=128
	mkfs.fat -F 32 ./run-ovmf/disk.img


.PHONY: mount-disk
mount-disk:
	sudo mount ./run-ovmf/disk.img ./run-ovmf/fs-mnt/ -o rw,umask=0000


.PHONY: umount-disk
umount-disk:
	sudo umount ./run-ovmf/fs-mnt || /bin/true


.PHONY: umount-disk-force
umount-disk-force:
	sudo umount -f ./run-ovmf/fs-mnt || /bin/true


.PHONY: umount-disk-lazy
umount-disk-lazy:
	sudo umount -l ./run-ovmf/fs-mnt 


.PHONY: --build
--build:
	build -n 4 -a X64 -t GCC5 -D E1000_ENABLE -p OvmfPkg/OvmfPkgX64.dsc


.PHONY: build
build: --build


.PHONY: --deploy
--deploy: build
	mkdir -p run-ovmf/debug
	mkdir -p run-ovmf/efis
	cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd run-ovmf/bios.bin
	cp Build/OvmfX64/DEBUG_GCC5/X64/*.debug run-ovmf/debug/
	cp Build/OvmfX64/DEBUG_GCC5/X64/*.efi run-ovmf/efis/
	cp run-ovmf/efis/* run-ovmf/fs-mnt/


.PHONY: deploy
deploy: umount-disk-force make-disk-img mount-disk --deploy umount-disk-lazy


QEMU := qemu-system-x86_64 


QEMU += -pflash run-ovmf/bios.bin  
QEMU += -debugcon file:debug.log -global isa-debugcon.iobase=0x402 

QEMU += -drive file=run-ovmf/disk.img 

QEMU += -enable-kvm 
QEMU += -m 4G  
QEMU += -machine q35 
QEMU += -cpu Icelake-Server 
QEMU += -rtc base=localtime  
QEMU += -nic model=e1000  

QEMU_NOGRAPHIC := -nographic  

QEMUG := -s -S


.PHONY: qemu
qemu:
	$(QEMU)


.PHONY: qemu-nographic
qemu-nographic:
	$(QEMU) $(QEMU_NOGRAPHIC)


.PHONY: qemug
qemug:
	$(QEMU) $(QEMUG)


.PHONY: run-qemu
run-qemu: deploy qemu


.PHONY: run-qemu-nographic
run-qemu-nographic: deploy qemu-nographic


.PHONY: all
all: deploy
