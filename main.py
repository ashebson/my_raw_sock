import socket
import os


def print_icmp(p, depth=0):
    print('ICMP:', end='\n' + '\t' * depth)
    print('Type:', int(p[0:8], 2), end='\n' + '\t' * depth)
    print('Code:', int(p[8:16], 2), end='\n' + '\t' * depth)
    print('Checksum:', p[16:32], end='\n' + '\t' * depth)
    print('Rest:', p[32:], end='\n' + '\t' * depth)


def print_tcp(p, depth=0):
    print('TCP:', end='\n' + '\t' * depth)
    print('Src Port:', int(p[0:16], 2), end='\n' + '\t' * depth)
    print('Dst Port:', int(p[16:32], 2), end='\n' + '\t' * depth)
    print('Seq:', int(p[32:64], 2), end='\n' + '\t' * depth)
    print('Ack:', int(p[64:96], 2), end='\n' + '\t' * depth)
    print('Data Offset:', int(p[96:100], 2), end='\n' + '\t' * depth)
    data_offset = int(p[96:100], 2) * 32
    print('Reserved:', p[100:103], end='\n' + '\t' * depth)
    print('Flags:', p[103], p[104], p[105], p[106], p[107], p[108], p[109], p[110], p[111], end='\n' + '\t' * depth)
    print('Window:', int(p[112:128], 2), end='\n' + '\t' * depth)
    print('Checksum:', p[128:144], end='\n' + '\t' * depth)
    print('Urg Ptr:', p[144:160], end='\n' + '\t' * depth)
    print('Options:', p[160:data_offset], end='\n' + '\t' * depth)
    print('Data:', bits_to_bytes(p[data_offset:]))


def get_ip_addr(b):
    addr = ''
    for i in range(4):
        addr += str(int(b[i * 8:(i + 1) * 8], 2)) + '.'
    return addr[:-1]


def get_bits(p):
    p = bin(int(p.hex(), 16))[2:]
    p = p.zfill(len(p) // 4 * 4 + 4)  # pad with zeros
    return p


def bits_to_bytes(b):
    return int(b, 2).to_bytes(len(b) // 8, 'big')


def print_ip(p, depth=0):
    print('IP:', end='\n' + '\t' * depth)
    print("version:", int(p[0:4], 2), end='\n' + '\t' * depth)
    print("Header Len:", int(p[4:8], 2), end='\n' + '\t' * depth)
    print("DSCP:", int(p[8:14], 2), end='\n' + '\t' * depth)
    print("ECN:", int(p[14:16], 2), end='\n' + '\t' * depth)
    print("Total Len:", int(p[16:32], 2), end='\n' + '\t' * depth)
    print("Identification:", int(p[32:48], 2), end='\n' + '\t' * depth)
    print("Flags:", p[48], p[49], p[50], end='\n' + '\t' * depth)
    print("Fragment Offset:", int(p[51:64], 2), end='\n' + '\t' * depth)
    print("TTL:", int(p[64:72], 2), end='\n' + '\t' * depth)
    print("Protocol:", int(p[72:80], 2), end='\n' + '\t' * depth)
    print("Header Checksum:", p[80:96], end='\n' + '\t' * depth)
    print("Src IP:", get_ip_addr(p[96:128]), end='\n' + '\t' * depth)
    print("Dst IP:", get_ip_addr(p[128:160]), end='\n' + '\t' * depth)
    # print_icmp(p[160:],depth+1)
    print_tcp(p[160:], depth + 1)


host = "192.168.1.237"
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sniffer.bind((host, 0))
p = sniffer.recv(65565)
p = get_bits(p)
print_ip(p, 1)