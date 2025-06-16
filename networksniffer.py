import socket
import struct
import binascii
import sys
import signal

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    protocol = ip_header[6]
    src_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])
    return src_addr, dest_addr, protocol, ihl * 4

def get_protocol_name(protocol_num):
    if protocol_num == 1:
        return "ICMP"
    elif protocol_num == 6:
        return "TCP"
    elif protocol_num == 17:
        return "UDP"
    else:
        return f"Unknown({protocol_num})"

def signal_handler(sig, frame):
    print("\nShutting down...")
    sys.exit(0)

def main():
    if sys.platform != "win32":
        print("This script only works on Windows")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        local_ip = get_local_ip()
        print(f"Binding to: {local_ip}")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        print("Starting packet capture... Press Ctrl+C to stop")
        
        while True:
            try:
                data, addr = s.recvfrom(65565)
                
                if len(data) < 20:
                    continue
                
                src_ip, dest_ip, protocol, ip_header_len = parse_ip_header(data)
                protocol_name = get_protocol_name(protocol)
                
                payload_start = ip_header_len
                payload = data[payload_start:payload_start + 20]
                hex_payload = binascii.hexlify(payload).decode('utf-8')
                
                print(f"Src: {src_ip:15} | Dest: {dest_ip:15} | Proto: {protocol_name:6} | Payload: {hex_payload}")
                
            except socket.error:
                continue
                
    except PermissionError:
        print("Error: Administrator privileges required for raw sockets")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except:
            pass

if __name__ == "__main__":
    main()