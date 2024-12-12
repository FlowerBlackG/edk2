
.PHONY: build
build:
	build -n 4 -a X64 -t GCC5 -D E1000_ENABLE -p OvmfPkg/OvmfPkgX64.dsc
	mkdir -p run-ovmf/debug
	mkdir -p run-ovmf/efis
	cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd run-ovmf/bios.bin
	cp Build/OvmfX64/DEBUG_GCC5/X64/*.debug run-ovmf/debug/
	cp Build/OvmfX64/DEBUG_GCC5/X64/*.efi run-ovmf/efis/


QEMU := qemu-system-x86_64 


QEMU += -pflash run-ovmf/bios.bin  
QEMU += -hda fat:rw:run-ovmf/hda-contents 
QEMU += -debugcon file:debug.log -global isa-debugcon.iobase=0x402 
QEMU += -drive file=fat:rw:run-ovmf/efis,id=fat32,format=raw  

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
run-qemu: build qemu

.PHONY: run-qemu-nographic
run-qemu-nographic: build qemu-nographic

