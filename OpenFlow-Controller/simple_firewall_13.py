from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib.packet import dhcp
from ryu.lib.packet import ether_types
from ryu.app import simple_switch_13
import re
import binascii
import struct

class SimpleFirewall13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # self.client_os = {}
        self.client_eth_os = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        actions = []
        os = ""

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)
        dhcp_pkt = pkt.get_protocols(dhcp.dhcp)

        # idnetify os of client
        if dhcp_pkt:
            # dhcp message type code equal either DHCP_DISCOVER or DHCP_REQUEST
            if dhcp_pkt[0].op == dhcp.DHCP_BOOT_REQUEST:
                host_name = []
                client_ip = 0

                dhcp_opts = dhcp_pkt[0].options
                self.logger.info(dhcp_opts)

                # opt is instance of dhcp.option
                for opt in dhcp_opts.option_list:
                    if dhcp.DHCP_HOST_NAME_OPT == opt.tag: # 12
                        host_name.append(opt.value)
                    elif 60 == opt.tag: # 60
                        host_name.append(opt.value)
                    # get ip address of client which dhcp server offered
                    elif dhcp.DHCP_REQUESTED_IP_ADDR_OPT == opt.tag: # 50
                        client_ip = opt.value

                for host in host_name:
                    if re.search("MSFT", host):
                        os = "Windows"
                        break
                    elif re.search("iPhone", host):
                        os = "iOS"
                        break
                    elif re.search("android", host):
                        os = "Android"
                        break
                    else:
                        os = ""
                
                self.logger.info(host_name)

                if len(os):
                    self.client_eth_os[src] = os
                    self.logger.info("--------------------------------------------")
                    self.logger.info("      OS           : %s ", os)
                    self.logger.info("      ethernet.src : %s ", eth.src)
                    self.logger.info("      ethernet.dst : %s ", eth.dst)
                    self.logger.info("      ipv4.src     : %s ", ipv4_pkt[0].src)
                    self.logger.info("      ipv4.dst     : %s ", ipv4_pkt[0].dst)
                    self.logger.info("--------------------------------------------")

                    print self.client_eth_os
                    
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # drop if not windows and destination is specific server which has 192.168.11.111
        if ipv4_pkt and \
            (ipv4_pkt[0].dst == "192.168.11.177" or \
            ipv4_pkt[0].dst == "192.168.11.194" or \
            ipv4_pkt[0].dst == "192.168.11.10" or \
            ipv4_pkt[0].dst == "192.168.11.11") and src in self.client_eth_os.keys() and self.client_eth_os[src] == "Windows":
            # self.logger.info("add flow to drop packet going to web server")
            self.logger.info("drop src mac %s\n", src)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            actions = []
            self.add_flow(datapath, 99, match, actions)
            return

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
