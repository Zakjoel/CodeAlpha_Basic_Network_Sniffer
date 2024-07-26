import socket 
from geoip import geolite2 
from scapy.all import *

                              ### get Sniff TCP , UDP And ICMP with scapy ###
print("################ STARTED ####################")
def analyzer(pkt):
    if pkt.haslayer(TCP):
        print("TCP Packet ...")
        print(pkt)
        print("-----------------------------------------------------")
      ########################## IP ################################
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
      ############################# MAC #############################
        mac_src = pkt.src
        mac_dst = pkt.dst
      ############################## PORT ############################
        src_port = pkt.sport
        dst_port = pkt.dport
      ############################ DATA And Length ###########################
        if pkt.haslayer(Raw):
            print(pkt[Raw].load)  
      #############################OUTPUT#############################
        print("SRC-IP : "+ src_ip) 
        print("DST-IP : "+ dst_ip) 
        print("mac_src : "+ mac_src) 
        print("mac_dst : "+ mac_dst) 
        print("port_src : "+ str(src_port) )  
        print("port_dst : "+ str(dst_port) ) 
        print("Packet_Size : "+ str(len(pkt[TCP]) ) + " Byte") 
        print("-----------------------------------------------------")

    if pkt.haslayer(UDP):
        print("UDP Packet ....")
        print(pkt)
        print("-----------------------------------------------------")
        ############################## IP ##########################
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
      ############################### MAC ###########################
        mac_src = pkt.src
        mac_dst = pkt.dst
      ############################# PORT ############################
        src_port = pkt.sport
        dst_port = pkt.dport
      ############################# DATA And Length ###################
        if pkt.haslayer(Raw):
            print(pkt[Raw].load)  
      ########################## OUTPUT ################################

        print("SRC-IP : "+ src_ip) 
        print("DST-IP : "+ dst_ip) 
        print("mac_src : "+ mac_src) 
        print("mac_dst : "+ mac_dst) 
        print("port_src : "+ str(src_port) )  
        print("port_dst : "+ str(dst_port) ) 
        print("Packet_Size : " + str(len(pkt[UDP]) ) + " Byte" )        
        print("-----------------------------------------------------")

    if pkt.haslayer(ICMP):
        print("ICMP Packet ....")
        print("-----------------------------------------------------")
        ########################### IP ############################
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].src
        ########################### MAC ###########################
        mac_src = pkt.src
        mac_dst = pkt.dst
        #################### DATA And Length ######################
        if pkt.haslayer(Raw):
            print(pkt[Raw].load)  
      ########################### OUTPUT ##############################
        print("SRC-IP : "+ src_ip) 
        print("DST-IP : "+ dst_ip) 
        print("mac_src : "+ mac_src) 
        print("mac_dst : "+ mac_dst) 
        print("Packet_Size : " + str(len(pkt[UDP]) ) + " Byte" )        
        print("-----------------------------------------------------")
                          ########################## Choce InterFaces To Sinff ############################
sniff(iface="Wi-Fi",prn=analyzer)
#sniff(iface="Ethernet",prn=analyzer)
#sniff(iface="wlan0",prn=analyzer)
#sniff(iface="eth0",prn=analyzer)


