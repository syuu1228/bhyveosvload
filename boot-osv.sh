#!/bin/sh

if [ $# -ne 1 ]; then 
	echo "usage: $0 <disk image>"
	exit 1
fi
echo "Preparing bridged networking"
ifconfig tap0 down

echo "Okay if you get the error \"does not exist\""
ifconfig tap0 destroy

echo "Okay if you get the error \"does not exist\""
ifconfig tap0 create

echo "May report that File exists"
ifconfig bridge0 addm tap0 addm em0 up
ifconfig tap0 up

echo "Destroying the guest if already running"
/usr/sbin/bhyvectl --destroy --vm=osv0 > /dev/null 2>&1

echo "Loading the guest kernel with /usr/sbin/bhyveload"
/usr/local/sbin/bhyveosvload -m 1024 -d $1 osv0

echo "Booting the guest kernel with /usr/sbin/bhyve"
echo "FreeBSD 8.* guests may exhibit a few second delay"
/usr/sbin/bhyve -c 1 -m 1024 -AI -H -P -g 0  \
-s 0:0,hostbridge \
-s 1:0,virtio-net,tap0 \
-s 2:0,virtio-blk,$1 \
-S 31,uart,stdio \
osv0
 
# Usage:
# bhyve [-aehABHIP][-g <gdb port>][-z <hz>][-s <pci>][-S <pci>][-p pincpu][
#-n <pci>][-m lowmem][-M highmem] <vm>
#       -a: local apic is in XAPIC mode (default is X2APIC)
#       -A: create an ACPI table
#       -g: gdb port (default is 6466 and 0 means don't open)
#       -c: # cpus (default 1)
#       -p: pin vcpu 'n' to host cpu 'pincpu + n'
#       -B: inject breakpoint exception on vm entry
#       -H: vmexit from the guest on hlt
#       -I: present an ioapic to the guest
#       -P: vmexit from the guest on pause
#        -e: exit on unhandled i/o access
#       -h: help
#       -z: guest hz (default is 100)
#       -s: <slot,driver,configinfo> PCI slot config
#       -S: <slot,driver,configinfo> legacy PCI slot config
#       -m: lowmem in MB
#       -x: mux vcpus to 1 hcpu
#       -t: mux vcpu timeslice hz (default 200)

