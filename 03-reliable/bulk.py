import sys
import string
import socket
import time

def server(port):
    with socket.socket() as s, open('server-output.dat', 'w') as fp:   # Make sure graceful exit
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        s.bind(('0.0.0.0', int(port)))
        s.listen(3)
        
        cs, addr = s.accept()
        print(addr)
        
        while True:
            data = cs.recv(1000)
            if data:
                fp.write(data.decode())
            else:
                break

def client(ip, port):
    with socket.socket() as s, open('client-input.dat', 'r') as fp:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # Disable Nagle
        s.connect((ip, int(port)))
        
        while True:
            data = fp.read(1000)
            if data:
                s.send(data.encode())
            else:
                break
        
        time.sleep(1)   # Avoid PSH-FIN aggregation
        
if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2])
    elif sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3])
