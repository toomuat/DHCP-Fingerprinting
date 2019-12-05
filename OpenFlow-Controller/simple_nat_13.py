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
from ryu.lib.packet import in_proto as inet

class SimpelNat13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpelNat13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # self.client_os = {}
        self.client_eth_os = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.server_eth = {
            "Windows": "02:42:C0:A8:0B:0A",
            "iOS":     "A8:13:74:93:DC:02",
            "Android": "02:42:C0:A8:0B:0B"
        }
        # assume clients request to 192.168.11.10 and switch modify 
        # request packet depending on it's os
        self.server_ip = {
            "Windows": "192.168.11.10",
            "iOS":     "192.168.11.11",
            "Android": "192.168.11.11"
        }
        actions = []
        os = ""
        added_flow_entry = False

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
                added_flow_entry = False

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
                    # self.client_os[client_ip] = os
                    self.client_eth_os[src] = os
                    self.logger.info("--------------------------------------------")
                    self.logger.info("      OS           : %s ", os)
                    self.logger.info("      ethernet.src : %s ", eth.src)
                    self.logger.info("      ethernet.dst : %s ", eth.dst)
                    self.logger.info("      ipv4.src     : %s ", ipv4_pkt[0].src)
                    self.logger.info("      ipv4.dst     : %s ", ipv4_pkt[0].dst)
                    self.logger.info("--------------------------------------------")
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # header modification when server reply to client
        if ipv4_pkt and ipv4_pkt[0].src in self.server_ip.values():
            self.logger.info("add flow from server to client")
            added_flow_entry = True
            kwargs = dict(in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        eth_dst=dst,
                        eth_src=src,
                        ipv4_src='192.168.11.11',
                        ip_proto=inet.IPPROTO_TCP)
            match = parser.OFPMatch(**kwargs)
            actions = [
                parser.OFPActionSetField(eth_src=self.server_eth["Windows"]),
                parser.OFPActionSetField(ipv4_src="192.168.11.10"),
                parser.OFPActionOutput(out_port)
            ]
            self.add_flow(datapath, 99, match, actions)

        # when accessed to Windows only server which has "192.168.11.10"
        if ipv4_pkt and ipv4_pkt[0].dst == "192.168.11.10" and src in self.client_eth_os.keys():
            if self.client_eth_os[src] == "Windows":
                self.logger.info("Windows can go through")
                # pass
            elif self.client_eth_os[src] == "Android" or self.client_eth_os[src] == "iOS":
                added_flow_entry = True
                # it seems flow entry doesn't updated
                # there are no flow entry which has priority 99 when executed ovs-vsctl dump-flows in switch
                actions = [
                    parser.OFPActionSetField(eth_dst=self.server_eth["Android"]),
                    parser.OFPActionSetField(ipv4_dst=self.server_ip["Android"]),
                    parser.OFPActionOutput(out_port)
                ]
                kwargs = dict(in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        eth_dst=dst,
                        eth_src=src,
                        ipv4_dst='192.168.11.10',
                        ip_proto=inet.IPPROTO_TCP)
                match = parser.OFPMatch(**kwargs)
                self.add_flow(datapath, 99, match, actions)
                self.logger.info("add flow for windows to redirect to 192.168.11.11 when accessed to 192.168.11.10")
                self.logger.info("src mac: %s", src)
                self.logger.info("dst mac: %s", dst)
                self.logger.info("src ip:  %s", ipv4_pkt[0].src)
                self.logger.info("dst ip:  %s", ipv4_pkt[0].dst)
                self.logger.info("--------------------------------------------")

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and not added_flow_entry:
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
