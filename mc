#!/usr/bin/env python3
import socket
import sys
import subprocess
import re

def get_interface_ip(interface_name):
    """Get the IP address of a network interface"""
    try:
        # Run ip addr show command
        result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                              capture_output=True, text=True, check=True)
        
        # Parse the output to find inet address
        for line in result.stdout.split('\n'):
            if 'inet ' in line and 'scope global' in line:
                # Extract IP address (before the '/')
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    return ip_match.group(1)
        
        raise ValueError(f"No IP address found for interface {interface_name}")
        
    except subprocess.CalledProcessError:
        raise ValueError(f"Interface {interface_name} not found or not accessible")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 listener.py <interface-name>")
        print("Example: python3 listener.py sfc0")
        sys.exit(1)
    
    interface_name = sys.argv[1]
    multicast_group = "239.254.64.2"
    port = 31103
    
    try:
        # Get interface IP address
        interface_ip = get_interface_ip(interface_name)
        print(f"Interface {interface_name} IP: {interface_ip}")
        
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', port))
        
        # Join multicast group on specified interface
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, 
                     socket.inet_aton(multicast_group) + socket.inet_aton(interface_ip))
        
        print(f"Listening on {interface_name} ({interface_ip}) for multicast {multicast_group}:{port}...")
        print("Press Ctrl+C to stop")
        
        while True:
            try:
                data, addr = s.recvfrom(1024)
                print(f"{addr}: {data.decode()}")
            except UnicodeDecodeError:
                print(f"{addr}: {data} (binary data)")
                
    except KeyboardInterrupt:
        print("\nStopping listener...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    main()


python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('192.168.163.2', 0))  # Bind to sfc0 IP
s.sendto(b'test message from sfc0', ('239.254.64.2', 31103))
s.close()
"
