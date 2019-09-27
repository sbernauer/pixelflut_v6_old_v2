#!/bin/bash

# Count (tx|rx)_(bytes|packets)_phy from ethtool and write them to /etc/pixelflut_v6_ethtool_statistics.txt

# /etc/crontab entry:
# * * * * * root /home/lwsops/pixelflut_v6/prometheus_exporter/cronjob.sh

> /etc/pixelflut_v6_ethtool_statistics.txt

for interface in $(/bin/ls /sys/class/net/); do
	ethtool -S $interface 2> /dev/null | grep -E '(tx|rx)_(bytes|packets)_phy' | sed -e 's/^[ ]*/pixelflut_v6_ethtool_/' | sed -e "s/: /\{device=\"${interface}\"\} /" >> /etc/pixelflut_v6_ethtool_statistics.txt
done
