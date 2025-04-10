FROM ubuntu:latest

RUN apt update && apt install -y tshark iproute2 iptables dnsmasq jq netmask bsdmainutils conntrack iputils-ping dnsutils  net-tools  ethtool
RUN apt update && apt install -y python3 python3-pip build-essential cmake libpcap-dev tcpdump vim netcat-traditional curl ipcalc libnats-dev 
RUN apt install -y openssl libssl-dev
RUN apt install -y gdb
WORKDIR /code/c-processor
