FROM ubuntu:latest

RUN apt update && apt install -y tshark iproute2 iptables dnsmasq jq netmask bsdmainutils conntrack iputils-ping dnsutils  net-tools  ethtool

# Disable IP forwarding our switch code will handle it!
RUN echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p
RUN apt update && apt install -y python3 python3-pip build-essential cmake libpcap-dev tcpdump vim netcat-traditional curl ipcalc libnats-dev 

WORKDIR /code/mitm/switch

