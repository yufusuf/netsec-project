import socket, os

def start_udp_listener():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind the socket to the port
    server_address = ( '', 8888)
    sock.bind(server_address)
    
    print("UDP listener started on port 8888")
    
    while True:
        data, address = sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {address}")
        print(data.decode())
        
        if data:
            sent = sock.sendto(data, address)
            print(f"Sent {sent} bytes back to {address}")

if __name__ == "__main__":
    start_udp_listener()