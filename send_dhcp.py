from scapy.all import *

def send_dhcp():
    srcMAC = "00:00:00:00:00:00 "

    packet = (
        Ether(src=srcMAC,dst="ff:ff:ff:ff:ff:ff")/
        IP(src="0.0.0.0",dst="255.255.255.255")/
        UDP(sport=68,dport=67)/
        BOOTP()/
        DHCP(options=[('message-type','request'), # 53
                        ('hostname','iPhone'), # 12
                        ("client_id", "00:00:00:00:00:00"), # 61 : 0028f87e2908
                        ("requested_addr", "192.168.3.10"), # 50
                        ("vendor_class_id", "MSFT 5.0"), # 60
                        ("vendor_class"), # 124
                        ('end')]) # 255
    )

    print("Sending DHCP discover")
    sendp(packet, verbose=0)

if __name__ == '__main__':
    send_dhcp()