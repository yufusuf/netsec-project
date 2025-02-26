FROM ubuntu:latest

RUN apt update && apt install -y tshark iproute2 iptables dnsmasq jq netmask bsdmainutils conntrack iputils-ping dnsutils  net-tools 

RUN apt update && apt install -y python3 python3-pip build-essential cmake libpcap-dev tcpdump vim netcat-traditional curl 

WORKDIR /code/sec