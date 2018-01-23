from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from kafka import KafkaProducer
import numpy as np
import netifaces

interfaces_docker = netifaces.interfaces()
print(interfaces_docker)


#Docker env variables
interface = interfaces_docker[1] 

producer = KafkaProducer(bootstrap_servers='10.40.39.22:1025')

NO_FLAGS = ""
NO_SEQ_NUMBER = ""
NO_WINDOW_NUMBER = 0


def extract_package_features(packet, ip=True):
    size = len(packet.payload)
    time = packet.time
    if ip:
        packet = packet.getlayer(IP)
        vector = np.array([])
        vector = np.append(vector, extract_ip_header_info(packet))

        if packet.haslayer(UDP):
            packet = packet.getlayer(UDP)
            vector = np.append(vector, extract_udp_header_info(packet))

        elif packet.haslayer(TCP):
            packet = packet.getlayer(TCP)
            vector = np.append(vector, extract_tcp_header_info(packet))
        else:
            return None

        vector = np.append(vector, time)
        vector = np.append(vector, size)
    # print(vector)

    # ORDER-> [SRC_IP, DST_IP, PROTOCOL, TTL_PACKAGE, IP_FLAGS, SRC_PORT, DST_PORT,
    #          TCP_FLAGS, SERVICE, SEQ_NUMBER, WINDOW_NUMBER, EPOCH_TIME, SIZE]
        return vector

    return None


def extract_ip_header_info(ip_package):
    src_ip = ip_package.src
    dst_ip = ip_package.dst
    protocol_ip = ip_package.proto
    ttl_ip = ip_package.ttl
    flags_ip = ip_package.flags # 2-> DON'T FRAGMENT

    return [src_ip, dst_ip, protocol_ip, ttl_ip, flags_ip]


def extract_tcp_header_info(tcp_packet):
    sport_tcp = tcp_packet.sport
    dport_tcp = tcp_packet.dport
    flags_tcp = tcp_packet.flags # 16-> ACK
    service_tcp = parse_tcp_service_from_port(dport_tcp)
    seq_number_tcp = tcp_packet.seq
    window_number_tcp = tcp_packet.window

    return [sport_tcp, dport_tcp, flags_tcp, service_tcp, seq_number_tcp, window_number_tcp]


def extract_udp_header_info(udp_package):
    sport_udp = udp_package.sport
    dport_udp = udp_package.dport
    service_udp = parse_udp_service_from_port(dport_udp)

    return [sport_udp, dport_udp, NO_FLAGS, service_udp, NO_SEQ_NUMBER, NO_WINDOW_NUMBER]


def parse_tcp_service_from_port(tcp_port):
    if tcp_port == 1:
        service = "tcpmux"
    elif tcp_port == 5:
        service = "rje"
    elif tcp_port == 7:
        service = "echo"
    elif tcp_port == 18:
        service = "msp"
    elif tcp_port == 20:
        service = "ftp_data"
    elif tcp_port == 21:
        service = "ftp_control"
    elif tcp_port == 22:
        service = "ssh"
    elif tcp_port == 23:
        service = "telnet"
    elif tcp_port == 25:
        service = "smtp"
    elif tcp_port == 29:
        service = "msg_icp"
    elif tcp_port == 37:
        service = "time"
    elif tcp_port == 42:
        service = "nameserv"
    elif tcp_port == 43:
        service = "whois"
    elif tcp_port == 49:
        service = "login"
    elif tcp_port == 70:
        service = "gopher_services"
    elif tcp_port == 79:
        service = "finger"
    elif tcp_port == 89:
        service = "http"
    elif tcp_port == 103:
        service = "x.400"
    elif tcp_port == 108:
        service = "gateway"
    elif tcp_port == 109:
        service = "pop2"
    elif tcp_port == 110:
        service = "pop3"
    elif tcp_port == 115:
        service = "sftp"
    elif tcp_port == 118:
        service = "sql_services"
    elif tcp_port == 119:
        service = "nntp"
    elif tcp_port == 143:
        service = "imap"
    elif tcp_port == 150:
        service = "netbios-ssn"
    elif tcp_port == 156:
        service = "sql_server"
    elif tcp_port == 179:
        service = "bgp"
    elif tcp_port == 190:
        service = "gacp"
    elif tcp_port == 194:
        service = "irc"
    elif tcp_port == 197:
        service = "dls"
    elif tcp_port == 289:
        service = "ldap"
    elif tcp_port == 389:
        service = "novell"
    elif tcp_port == 443:
        service = "https"
    elif tcp_port == 444:
        service = "snpp"
    elif tcp_port == 445:
        service = "microsoft_ds"
    elif tcp_port == 458:
        service = "apple_quicktime"
    elif tcp_port == 546:
        service = "dhcp_client"
    elif tcp_port == 547:
        service = "dhcp_server"
    elif tcp_port == 563:
        service = "snews"
    elif tcp_port == 569:
        service = "msn"
    elif tcp_port == 1080:
        service = "socks"
    else:
        service = tcp_port

    return service


def parse_udp_service_from_port(udp_port):
    if udp_port == 53:
        service = "dns"
    elif udp_port == 69:
        service = "tftp"
    elif udp_port == 123:
        service = "ntp"
    elif udp_port == 137:
        service = "netbios-dgm"
    elif udp_port == 161:
        service = "snmp"
    else:
        service = udp_port

    return service

def is_valid_protocol(incoming_package):
    if incoming_package.haslayer(IP) and (incoming_package.haslayer(TCP) or incoming_package.haslayer(UDP)):
        return True
    else:
        return False

def filter_and_send(raw_package):
    if is_valid_protocol(raw_package):
        package_info = extract_package_features(raw_package)
        if package_info is not None:
            producer.send('sniffer', np.array_str(package_info).encode())
            print(package_info)
        #We have to identify the source of this package in consumer -> MAC
        #Care fragmented packages in deployment

def start_sniffing(interface=interface, filter="ip", func=filter_and_send):
    sniff(iface=interface, filter=filter, prn=func)

start_sniffing()
