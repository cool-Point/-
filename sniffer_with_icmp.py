import socket

import os
import struct
from ctypes import *

host = "192.168.3.12"

class IP(Structure):

    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte, 8),
        ("len",           c_ushort, 16),
        ("id",            c_ushort, 16),
        ("offset",        c_ushort, 16),
        ("ttl",           c_ubyte, 8),
        ("protocol_num",  c_ubyte, 8),
        ("sum",           c_ushort, 16),
        ("src",           c_uint, 32),
        ("dst",           c_uint, 32),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_map)

class ICMP(Structure):

    _fields_ = [
        ("type",         c_ubyte, 4),
        ("code",         c_ubyte, 4),
        ("checksum",     c_ushort, 16),
        ("unused",       c_ushort, 16),
        ("next_hop_mtu", c_ushort, 16),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


try:

    while True:

        raw_buffer = sniffer.recvfrom(65565)[0]

        ip_header = IP(raw_buffer)

        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        if ip_header.protocol == "ICMP":

            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            icmp_header = ICMP(buf)

            print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
