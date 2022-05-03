from dataclasses import dataclass
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
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

        self.macs = {1:{'192.168.0.10':'00:00:00:00:00:01','192.168.0.11':'00:00:00:00:00:02','192.168.0.12':'00:00:00:00:00:03'},
                    2:{'192.168.1.10':'00:00:00:00:01:01','192.168.1.11':'00:00:00:00:01:02','192.168.1.12':'00:00:00:00:01:03'},
                    3:{'192.168.2.10':'00:00:00:00:02:01','192.168.2.11':'00:00:00:00:02:02','192.168.2.12':'00:00:00:00:02:03'}}

        self.my_ports_to_mac = {}


        # deixar estatico
        # depois injetar regras
        # só depois se mete dinamico

        # se o trafico for para ele vem ser in_port
        self.logger.info("Comecei")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Fiz alguma coisa pelo menos")
        print("Fiz alguma coisa pelo menos")
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
            # o output é este
            # {4294967294: '76:96:ed:30:67:46', 4: '76:fc:31:71:ac:a7', 1: '76:1f:97:71:84:92', 2: 'b6:72:46:da:68:c2', 3: 'ba:ce:4d:5f:a7:32'}
            # o que é aquele primeiro - porta de lo
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
        self.logger.info("Recebi um pacote")
        print("revebi um pacote")
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
        '''
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        out_port = None


        # primeiro nao utilizar mod flows
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return'''
        
        if ip := pkt.get_protocol(arp.arp):
            src_mac = ip.src_mac
            src_ip = ip.src_ip
            dst_ip = ip.dst_ip

            #Adiciona o ip para saber os vizinhos dele
            self.routing_table[dpid][src_ip] = in_port

            # verificar qual é o tipo de arp 
            if ip.opcode == arp.ARP_REQUEST:
                # Verificar se estao a pedir o mac dele (?)
                    if '254' in dst_ip:
                        print("entrei")
                        '''
                        # retira o endereco mac de origem e coloca o dele
                        out_port = in_port

                        ip.src_mac = self.my_ports_to_mac.get(in_port)
                        ip.dst_mac = src_mac
                        ip.src_ip = dst_ip
                        ip.dst_ip = src_ip

                        ip.opcode = arp.ARP_REPLY
                        

                        actions = [parser.OFPActionOutput(out_port)]

                        out = parser.OFPPacketOut(datapath=datapath, 
                                                buffer_id= ofproto.OFP_NO_BUFFER,
                                                in_port=ofproto.OFPP_CONTROLLER, 
                                                actions=actions, 
                                                data=msg.data)
                        datapath.send_msg(out)
                        '''
                        # retira o endereco mac de origem e coloca o dele
                        out_port = in_port
                        mac = self.my_ports_to_mac.get(in_port)

                        arp_reply_pkt = packet.Packet()

                        e = ethernet.ethernet(src_mac, mac, ether_types.ETH_TYPE_ARP)
                        arp_reply_pkt.add_protocol(e)

                        a = arp.arp(datapath.id, 0x0800, 6, 4, arp.ARP_REPLY, mac, dst_ip, src_mac, src_ip)
                        arp_reply_pkt.add_protocol(a)

                        arp_reply_pkt.serialize()

                        out = parser.OFPPacketOut(datapath=datapath, 
                                                buffer_id= ofproto.OFP_NO_BUFFER,
                                                in_port=ofproto.OFPP_CONTROLLER, 
                                                actions=[parser.OFPActionOutput(out_port)], 
                                                data=arp_reply_pkt.data)
                        datapath.send_msg(out)
                        
            return
                
        '''  
        elif ip := pkt.get_protocol(ipv4.ipv4): 
            src_ip = ip.src
            dst_ip = ip.dst
            # pacote ICMP esta dentro do IP
            #if ping := pkt.get_protocol(icmp.icmp):
            #    pass

                # a destination esta na parte do IP
                # não é preciso ver isto


                # se nao for para mim dou foward
                # se for para mim responder (mais tarde)
            self.routing_table[dpid][src_ip] = in_port

            
            for prefix in self.subredes:
                if prefix is str and prefix in dst_ip:
                    # retira o endereco mac de origem e coloca o dele
                    out_port = self.subredes.get(prefix)

                    eth.src = self.my_ports_to_mac.get(out_port)

                    eth.dst = self.macs.get(dpid).get(dst_ip)

                    break

            
            
            
            if dst_ip in self.routing_table[dpid]:
                out_port = self.routing_table[dpid][dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD

            

        if out_port == None:
            return # ou discarta o pacote no switch
 
        actions = [parser.OFPActionOutput(out_port)]
        
        #data = None
        #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)


        # OCDIGO DO ARP ANTIGO
        if prefix is str and prefix in dst_ip:
                        
                        
                        

                        
        '''

        
        