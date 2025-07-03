python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 31103))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, 
             socket.inet_aton('239.254.64.2') + socket.inet_aton('192.168.163.2'))
print('Listening on sfc0 (192.168.163.2) for multicast 239.254.64.2:31103...')
while True: 
    data, addr = s.recvfrom(1024)
    print(f'{addr}: {data.decode()}')
"
