# pixelflut_v6_client
This program generates traffic to draw rectangles in random colors at a pixelflut_v6 server.
For pixelflut_v6 see https://entropia.de/GPN17:Pingxelflut

# Installing
This project uses DPDK.
Please take a look if your hardware is supported at http://core.dpdk.org/supported/
It requires a compiled DPDK, follow the instructions for setting DPDK up at http://doc.dpdk.org/guides/linux_gsg/

## Dependencies
```
apt install libnuma-dev linux-source linux-headers-4.9.0-9-all libsdl2-dev git build-essential libsdl2-dev libpthread-stubs0-dev libvncserver-dev libnuma-dev
```
You should adopt the linux-headers-x.x.x-x-all package to your kernel version

## Build and set up dpdk
If not done already done build DPDK: http://doc.dpdk.org/guides/linux_gsg/build_dpdk.html
### Allocate huge pages
```
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
```

### Bind nic
```
export RTE_SDK=/my/path/to/dpdk/folder
$RTE_SDK/usertools/dpdk-devbind.py --status
modprobe uio_pci_generic
# optional, if NIC is active take it first down: ip link set dev eno1 down
$RTE_SDK/usertools/dpdk-devbind.py --bind=uio_pci_generic 0000:00:19.0 # Change to your pci-adress
```

## Build pixelflut_v6_client
```
export RTE_SDK=/my/path/to/dpdk/folder
make
```

# Run Build pixelflut_v6_client
Make shure, that you change MAC-Adresses and IPv6 /64-subnet to your desired adresses and recompile.
The adresses are currently not configurable.
First parameters are EAL-Parameters from DPDK (see http://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
Then follows a "--", and then the parameters to the pixelflut_v6_client
Parameters are:
```
build/pixelflut_v6_client [EAL options] -- -p PORTMASK [-q NQ]
  -p PORTMASK: hexadecimal bitmask of ports to configure
  -q NQ: number of queue (=ports) per lcore (default is 1)
  -r NQ: number of queue (=threads) per port (default is 1)
  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)
```
For example to generate traffic on 1 port (the first port available) using 1 core use:
```
sudo build/pixelflut_v6_client -l 0 -- -p 0x1
```

To use 8 cores on 1 port (and more frequent statistics):
```
sudo build/pixelflut_v6_client -l 0-7 -- -p 0x1 -r 8 -T 1
```

To use 16 cores on 4 ports:
```
sudo build/pixelflut_v6_client -l 0-15 -- -p 0xf -r 4 -T 1
```

### TODOs
- Make MAC-Adress configurable instead of compiling in. MAC-Adress should be configurable for each port independent.
- Make IPv6 /64-network configurable instead of compiling in
- Remove unnecessary code imported from skeleton 
