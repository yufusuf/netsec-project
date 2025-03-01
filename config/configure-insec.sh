#!/bin/bash
ip route add 10.1.0.0/16 via 10.0.0.2 dev eth0
echo '10.0.0.21 insec' >> /etc/hosts
echo '10.1.0.21 sec' >> /etc/hosts

sysctl net.ipv4.ip_forward=0
sysctl -p

systemctl start nftables.service

ethtool --offload eth0 tx off
nft add table input_table 
nft 'add chain input_table input {type filter hook input priority -300;}'
nft 'add rule input_table input ip protocol udp udp checksum set 0'


while true; 
    do sleep 0.01;
    done