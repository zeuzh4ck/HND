#!/usr/bin/python3
import socket
from struct import *
from ctypes import *

class IPv6 (Structure):
    _fields_ = [
            ("version",c_ubyte,4),
            ("priority",c_ubyte),
            ("flow_label",c_uint32,20),
            ("payload_length",c_ushort),
            ("next_head",c_ubyte),
            ("hop_limit",c_ubyte),
            ("src_ip1",c_ushort),
            ("src_ip2",c_ushort),
            ("src_ip3",c_ushort),
            ("src_ip4",c_ushort),
            ("src_ip5",c_ushort),
            ("src_ip6",c_ushort),
            ("src_ip7",c_ushort),
            ("src_ip8",c_ushort),
            ("des_ip1",c_ushort),
            ("des_ip2",c_ushort),
            ("des_ip3",c_ushort),
            ("des_ip4",c_ushort),
            ("des_ip5",c_ushort),
            ("des_ip6",c_ushort),
            ("des_ip7",c_ushort),
            ("des_ip8",c_ushort),
            ]

    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer= None):
        self.version=int(self.version)
        self.priority=int(self.priority)
        self.flow_label=int(self.flow_label)
        self.payload_length=int(self.payload_length)
        self.next_head=int(self.next_head)
        self.hop_limit=int(self.hop_limit)

        self.des_ip = (str(hex(self.des_ip1)[2:]).zfill(2)+str(hex(self.des_ip2)[2:]).zfill(2)+":"+str(hex(self.des_ip3)[2:]).zfill(2)+str(hex(self.des_ip4)[2:]).zfill(2)+":"+str(hex(self.des_ip5)[2:]).zfill(2)+str(hex(self.des_mac6)[2:]).zfill(2)+":"+str(hex(self.des_ip7)[2:]).zfill(2)+str(hex(self.des_ip8)[2:]).zfill(2)).upper()

        self.src_ip = (str(hex(self.src_ip1)[2:]).zfill(2)+str(hex(self.src_ip2)[2:]).zfill(2)+":"+str(hex(self.src_ip3)[2:]).zfill(2)+str(hex(self.src_ip4)[2:]).zfill(2)+":"+str(hex(self.src_ip5)[2:]).zfill(2)+str(hex(self.src_mac6)[2:]).zfill(2)+":"+str(hex(self.src_ip7)[2:]).zfill(2)+str(hex(self.src_ip8)[2:]).zfill(2)).upper()



class ARP (Structure):
    _fields_ = [
            ("hardware_type",c_ushort),
            ("prtocol_type",c_ushort),
            ("hardware_size",c_ubyte),
            ("protocol_size",c_ubyte),
            ("opcode",c_ushort),
            ("src_mac1",c_ubyte),
            ("src_mac2",c_ubyte),
            ("src_mac3",c_ubyte),
            ("src_mac4",c_ubyte),
            ("src_mac5",c_ubyte),
            ("src_mac6",c_ubyte),
            ("Src_IP",c_uint32),
            ("des_mac1",c_ubyte),
            ("des_mac2",c_ubyte),
            ("des_mac3",c_ubyte),
            ("des_mac4",c_ubyte),
            ("des_mac5",c_ubyte),
            ("des_mac6",c_ubyte),
            ("Des_IP",c_uint32)

            ]

    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer= None):
        self.hardware_type=socket.ntohs(self.hardware_type)
        self.prtocol_type=socket.ntohs(self.prtocol_type)
        self.hardware_size=socket.ntohs(self.hardware_size)
        self.protocol_size=socket.ntohs(self.protocol_size)
        self.opcode=socket.ntohs(self.opcode)
        self.Src_IP_Add=socket.inet_ntoa(pack("@I",Src_IP_Add))
        self.Dst_IP_Add=socket.inet_ntoa(pack("@I",Dst_IP_Add))

        self.des_mac = (str(hex(self.des_mac1)[2:]).zfill(2)+":"+str(hex(self.des_mac2)[2:]).zfill(2)+":"+str(hex(self.des_mac3)[2:]).zfill(2)+":"+str(hex(self.des_mac4)[2:]).zfill(2)+":"+str(hex(self.des_mac5)[2:]).zfill(2)+":"+str(hex(self.des_mac6)[2:]).zfill(2)).upper()

        self.src_mac =(str(hex(self.src_mac1)[2:]).zfill(2)+":"+str(hex(self.src_mac2)[2:]).zfill(2)+":"+str(hex(self.src_mac3)[2:]).zfill(2)+":"+str(hex(self.src_mac4)[2:]).zfill(2)+":"+str(hex(self.src_mac5)[2:]).zfill(2)+":"+str(hex(self.src_mac6)[2:]).zfill(2)).upper()



class UDP (Structure):
    _fields_ = [
            ("src_port",c_ushort),
            ("des_port",c_ushort),
            ("len",c_ushort),
            ("chk_sum",c_ushort),
            ]

    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer= None):
        self.src_port=socket.ntohs(self.src_port)
        self.des_port=socket.ntohs(self.des_port)
        self.len=socket.ntohs(self.len)
        self.chk_sum=socket.ntohs(self.chk_sum)


class TCP (Structure):
    _fields_ = [
            ("src_port",c_ushort),
            ("des_port",c_ushort),
            ("seq_num",c_uint32),
            ("ack_num",c_uint32),
            ("flag", c_ushort),
            ]

    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
   
    def __init__(self, socket_buffer= None):
        self.src_port=socket.htons(self.src_port)
        self.des_port=socket.htons(self.des_port)
        self.seq_num =socket.htonl(self.seq_num)
        self.ack_num =socket.htonl(self.ack_num)
        self.flag = socket.htons(self.flag)


class ICMP (Structure):
    _fields_ = [
            ("type",c_ubyte),
            ("code",c_ubyte),
            ("chk_sum",c_ushort) 
                        ]
    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer= None):
        
        self.type=int(self.type)
        self.code=int(self.code)
        self.chk_sum=socket.ntohs(self.chk_sum)


class IPv4 (Structure):
    _fields_ = [
            ("ihl",c_ubyte, 4),
            ("version",c_ubyte, 4),
            ("tos",c_ubyte),
            ("len",c_ushort),
            ("id", c_ushort),
            ("offset",c_ushort),
            ("ttl",c_ubyte),
            ("protocol_num",c_ubyte),
            ("sum", c_ushort),
            ("src", c_uint32),
            ("dst", c_uint32)
                        ]
    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer= None):
        #map protocol constants to their names
        self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}

        self.src_address=socket.inet_ntoa(pack("@I",self.src))
        self.dst_address=socket.inet_ntoa(pack("@I",self.dst))

    #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
    	    self.protocol = str(self.protocol_num)

class eth_head (Structure):
    _fields_ = [
	    ("des_mac1",c_ubyte),
            ("des_mac2",c_ubyte),
            ("des_mac3",c_ubyte),
            ("des_mac4",c_ubyte),
            ("des_mac5",c_ubyte),
            ("des_mac6",c_ubyte),
            ("src_mac1",c_ubyte),
            ("src_mac2",c_ubyte),
            ("src_mac3",c_ubyte),
            ("src_mac4",c_ubyte),
            ("src_mac5",c_ubyte),
            ("src_mac6",c_ubyte),
	    ("proto",c_ushort) ]

    def __new__ (self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
   
    def __init__(self, socket_buffer= None):
        #map protocol constants to their names
        self.protocol_map = {8:"IPv4",326:"APR",0x08DD:"IPv6"}
        

        self.des_mac = (str(hex(self.des_mac1)[2:]).zfill(2)+":"+str(hex(self.des_mac2)[2:]).zfill(2)+":"+str(hex(self.des_mac3)[2:]).zfill(2)+":"+str(hex(self.des_mac4)[2:]).zfill(2)+":"+str(hex(self.des_mac5)[2:]).zfill(2)+":"+str(hex(self.des_mac6)[2:]).zfill(2)).upper()
        
        self.src_mac =(str(hex(self.src_mac1)[2:]).zfill(2)+":"+str(hex(self.src_mac2)[2:]).zfill(2)+":"+str(hex(self.src_mac3)[2:]).zfill(2)+":"+str(hex(self.src_mac4)[2:]).zfill(2)+":"+str(hex(self.src_mac5)[2:]).zfill(2)+":"+str(hex(self.src_mac6)[2:]).zfill(2)).upper()



    #human readable protocol
        
       # try:

         #   self.proto = self.protocol_map[self.proto]
        #except:
    	  #  self.proto = str(self.proto)
try:

    sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('ens33', 0))

except Exception as e:
    print(e)
    exit(1)


#MAIN_FUCNTION............................................
while True:
    print("===================================================================================================================")
    print("[Eth_HEADER]","\t",":",end='')

    try:
        data =sock.recvfrom(65565)[0]
        ip = eth_head(data[:14])
        print('\t',ip.src_mac,end='\t')
        print (" -> ", end='\t')
        print(ip.des_mac, end='\t')

        print(" | ",end='')
        print(ip.protocol_map[ip.proto],end='')
        print("|")
        

        if ip.proto==8:
            print("[IP_HEADER]","\t",":",end = '\t')

            ipv4 = IPv4(data[14:])

            print(ipv4.src_address,end='\t')
            print (" -> ", end='\t')
            print(ipv4.dst_address, end='')
            print(" | ",end='')
            print(ipv4.protocol, end='')
            print(" | ")
            

            if ipv4.protocol == "ICMP":
                icmp = ICMP(data[34:])
                print ("[ICMP_HEADER]","\t",":",end='\t')
                print("||",end='')
                print ("TYPE:",icmp.type, end='||')
                print ("CODE:",icmp.code, end='||')
                print ("CHK_SUM:",icmp.chk_sum,end='')
                print("||")


            elif ipv4.protocol == "TCP":
                tcp = TCP(data[34:])
                print("[TCP_HEADER]",'\t',":",end='\t')
                print("SRC_PORT =",tcp.src_port,end='||')
                print("DES_PORT =",tcp.des_port,end='||')
                print("SEQ_num =",tcp.seq_num,end='||')
                print("ACK_num =",tcp.ack_num, end='||')
                print("FLAG :",end='')
                if tcp.flag==20496:
                    print("[ACK]")
                elif tcp.flag==40962:
                    print("[SYN]")
                elif tcp.flag ==24594:
                    print("[SYN, ACK]")
                elif tcp.flag == 20497:
                    print("[FIN, ACK]")
                elif tcp.flag==20504:
                    print("[PSH, ACK]")
                elif tcp.flag==20484:
                    print("[RST]")
                else:
                    print (tcp.flag)
                

            elif ipv4.protocol == "UDP":
                udp = UDP(data[34:])
                print("[UDP_HEADER]",'\t',":",end='\t')
                print("SRC_PORT =",udp.src_port,end='||')
                print("DES_PORT =",udp.des_port,end='||')
                print("Length =", udp.len,end='||')
                print("CHK_SUM =",udp.chk_sum,end='')
                print("||")
            
            else:
                print(data[34:])

        if ip.proto==806:
            print("[ARP_HEADER]","\t",":",end = '\t')

            arp = ARP(data[14:])

            print(arp.Src_IP,end='\t')
            print (" -> ", end='\t')
            print(arp.Dst_IP, end='')
            print(" | ",end='')
            print(ipv4.protocol, end='')
            print(" | ")

        if ip.proto==IPv6:
            print("[IPv6_HEADER]","\t",":",end = '\t')

            ipv6 = IPv6(data[14:])

            print(ipv6.src_ip,end='\t')
            print (" -> ", end='\t')
            print(ipv6.dst_ip, end='')
            print(" | ",end='')
            print(ipv6.next_head, end='')
            print(" | ")


                
    except KeyboardInterrupt:
        print("[-] Exiting ...")
        exit(1)
    except Exception as e:
        print(e)

