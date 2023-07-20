from scapy.all import *
from scapy.layers.dns import DNS

def process_dns_packet(packet):
    dns_layer = packet.getlayer(DNS)
    if dns_layer is not None:
        if dns_layer.qr == 0:  # Check if it's a DNS query
            domain = dns_layer.qd.qname.decode('utf-8')
            send_to_api(domain, packet)

def send_to_api(domain, packet):
    import requests
    data = {'domain': domain}
    response = requests.post(url+'/api', json=data)
    print(packet)
    print(response.text)
url = input("Enter the API URL: ")  # Nhận URL từ bàn phím
# Bắt các gói tin DNS
sniff(filter='udp and port 53', prn=process_dns_packet)
