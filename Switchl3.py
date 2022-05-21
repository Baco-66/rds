from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, icmp, ethernet, ipv4



class Simple13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Simple13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Routing table {ip:port}
        # isto é basicamente a CAM adress
        self.routing_table = {}
        self.subredes = {'192.168.0':1,'192.168.1':2,'192.168.2':3}
        self.message_queue = {}

        # arps vale pouco depois faz-se isto
        self.macs = {1:{'192.168.0.10':'00:00:00:00:00:01','192.168.0.11':'00:00:00:00:00:02','192.168.0.12':'00:00:00:00:00:03'},
                    2:{'192.168.1.10':'00:00:00:00:01:01','192.168.1.11':'00:00:00:00:01:02','192.168.1.12':'00:00:00:00:01:03'},
                    3:{'192.168.2.10':'00:00:00:00:02:01','192.168.2.11':'00:00:00:00:02:02','192.168.2.12':'00:00:00:00:02:03'}}

        self.my_ports_to_mac = {}



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath)
        datapath.send_msg(req)

        
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.my_ports_to_mac.setdefault(dpid, {})
        for p in ev.msg.body:
            self.my_ports_to_mac[dpid][p.port_no] = p.hw_addr


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.routing_table.setdefault(dpid, {})
        self.message_queue.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet) 


        '''
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        '''
        
        if ip := pkt.get_protocol(arp.arp):
            src_mac = ip.src_mac
            src_ip = ip.src_ip
            dst_ip = ip.dst_ip

            #Adiciona o ip para saber os vizinhos dele
            self.routing_table[dpid][src_ip] = in_port

            # verificar qual é o tipo de arp 
            if ip.opcode == arp.ARP_REQUEST:
                # Verificar se estao a pedir o mac dele
                if '254' in dst_ip:
                    # retira o endereco mac de origem e coloca o dele
                    out_port = in_port
                    exit = parser.OFPActionOutput(out_port)

                    mac = self.my_ports_to_mac[datapath.id].get(out_port)

                    pkt = packet.Packet()

                    e = ethernet.ethernet(dst=src_mac, src=mac, ethertype=ether_types.ETH_TYPE_ARP)
                    pkt.add_protocol(e)

                    a = arp.arp(opcode=arp.ARP_REPLY, src_mac=mac, src_ip=dst_ip, dst_mac=src_mac, dst_ip=src_ip)
                    pkt.add_protocol(a)

                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op=arp.ARP_REQUEST, arp_spa=src_ip, arp_tpa=dst_ip)
                    set_eth_src = ofproto_v1_3_parser.OFPActionSetField(eth_src=mac)
                    set_eth_dst = ofproto_v1_3_parser.OFPActionSetField(eth_dst=src_mac)

                    set_arp_type = ofproto_v1_3_parser.OFPActionSetField(arp_op=arp.ARP_REPLY)
                    set_arp_spa = ofproto_v1_3_parser.OFPActionSetField(arp_spa=dst_ip)
                    set_arp_tpa = ofproto_v1_3_parser.OFPActionSetField(arp_tpa=src_ip)
                    set_arp_sha = ofproto_v1_3_parser.OFPActionSetField(arp_sha=mac)
                    set_arp_tha = ofproto_v1_3_parser.OFPActionSetField(arp_tha=src_mac)

                    actions = [set_eth_src,set_eth_dst,set_arp_type,set_arp_spa,set_arp_tpa,set_arp_sha,set_arp_tha,exit]
                else:
                    return
            else:
                return
        elif ip := pkt.get_protocol(ipv4.ipv4): 
            src_ip = ip.src
            dst_ip = ip.dst

            self.routing_table[dpid][src_ip] = in_port

            if r := pkt.get_protocol(icmp.icmp) and '254' in dst_ip:
                # retira o endereco mac de origem e coloca o dele
                out_port = in_port
                exit = parser.OFPActionOutput(out_port)

                eth.src = self.my_ports_to_mac[datapath.id].get(out_port)
                eth.dst = self.macs.get(dpid).get(src_ip)

                ip.src = dst_ip
                ip.dst = src_ip

                r.type_= icmp.ICMP_ECHO_REPLY

                # ip_proto= 1 fica feio mas nao sei o que por
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip, ip_proto=1 ,icmpv4_type=icmp.ICMP_ECHO_REQUEST)
                set_eth_src = ofproto_v1_3_parser.OFPActionSetField(eth_src=eth.src)
                set_eth_dst = ofproto_v1_3_parser.OFPActionSetField(eth_dst=eth.dst)

                set_ip_src = ofproto_v1_3_parser.OFPActionSetField(ipv4_src=ip.src)
                set_ip_dst = ofproto_v1_3_parser.OFPActionSetField(ipv4_dst=ip.dst)

                set_icmp_type = ofproto_v1_3_parser.OFPActionSetField(icmpv4_type=icmp.ICMP_ECHO_REPLY)

                actions = [set_eth_src,set_eth_dst,set_ip_src,set_ip_dst,set_icmp_type,exit]

                '''
                out_port = in_port
                mac = self.my_ports_to_mac[datapath.id].get(out_port)

                reply_pkt = packet.Packet()

                e = ethernet.ethernet(dst=self.macs.get(dpid).get(src_ip), src=mac, ethertype=ether_types.ETH_TYPE_IP)
                reply_pkt.add_protocol(e)

                i = ipv4.ipv4(proto=ip.proto ,src=dst_ip, dst=src_ip)
                reply_pkt.add_protocol(i)

                r = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY)
                reply_pkt.add_protocol(r)

                reply_pkt.serialize()

                out = parser.OFPPacketOut(datapath=datapath, 
                                        buffer_id= ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER, 
                                        actions=[parser.OFPActionOutput(out_port)], 
                                        data=reply_pkt.data)
                datapath.send_msg(out)
                '''
            else:
                out_port = None
                for prefix in self.subredes:
                    if dst_ip.startswith(prefix):
                        # retira o endereco mac de origem e coloca o dele
                        out_port = self.subredes.get(prefix)
                        exit = parser.OFPActionOutput(out_port)

                        eth.src = self.my_ports_to_mac[datapath.id].get(out_port)
                        eth.dst = self.macs.get(out_port).get(dst_ip)

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                        set_eth_src = ofproto_v1_3_parser.OFPActionSetField(eth_src=eth.src)
                        set_eth_dst = ofproto_v1_3_parser.OFPActionSetField(eth_dst=eth.dst)
                        break
                
                if out_port == None:
                    print("Não encontrou este endereço na tabela, endereço inválido")
                    return # ou discarta o pacote no switc

                actions = [set_eth_src,set_eth_dst,exit]
        else:
            return

        pkt.serialize()
        # Se o buffer id for null, data tem de ter cenas 
        # Se buffer id for o que vem na msg inicial data tem de ser null
        out = parser.OFPPacketOut(datapath=datapath, 
                                buffer_id= ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, 
                                actions=[exit], 
                                data=pkt.data)
        datapath.send_msg(out)

        self.add_flow(datapath, 1, match, actions)
        


        


