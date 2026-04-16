from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from collections import defaultdict
import time

class TrafficClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifier, self).__init__(*args, **kwargs)

        # MAC learning table
        self.mac_to_port = {}

        # Traffic counters per protocol
        self.stats = defaultdict(int)   # {'TCP':0, 'UDP':0, 'ICMP':0, 'Other':0}
        self.byte_stats = defaultdict(int)

        # For periodic reporting
        self.last_report = time.time()
        self.report_interval = 10  # seconds

    # ── Called once when switch connects ──────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Default rule: send all unmatched packets to controller
        match  = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s connected", datapath.id)

    # ── Helper: install a flow rule ────────────────────────────────────────
    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)

    # ── Main event: packet arrives at controller ───────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        # ── CLASSIFY the packet ──────────────────────────────────────────
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        proto_name = "Other"

        if tcp_pkt:
            proto_name = "TCP"
            self.stats["TCP"]  += 1
            self.byte_stats["TCP"] += len(msg.data)

            # Install flow rule for TCP so future packets bypass controller
            if out_port != ofproto.OFPP_FLOOD and ip_pkt:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ip_proto=6,   # TCP
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 2, match, actions, idle=10)

        elif udp_pkt:
            proto_name = "UDP"
            self.stats["UDP"]  += 1
            self.byte_stats["UDP"] += len(msg.data)

            if out_port != ofproto.OFPP_FLOOD and ip_pkt:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ip_proto=17,  # UDP
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 2, match, actions, idle=10)

        elif icmp_pkt:
            proto_name = "ICMP"
            self.stats["ICMP"] += 1
            self.byte_stats["ICMP"] += len(msg.data)

            if out_port != ofproto.OFPP_FLOOD and ip_pkt:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ip_proto=1,   # ICMP
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 2, match, actions, idle=10)

        else:
            self.stats["Other"] += 1

        # Log each classified packet
        src_ip = ip_pkt.src if ip_pkt else "N/A"
        dst_ip = ip_pkt.dst if ip_pkt else "N/A"
        self.logger.info(
            "[%s] %s -> %s | port: %s -> %s",
            proto_name, src_ip, dst_ip, in_port, out_port)

        # Forward the packet
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

        # ── Print statistics every 10 seconds ───────────────────────────
        now = time.time()
        if now - self.last_report >= self.report_interval:
            self.print_stats()
            self.last_report = now

    # ── Print traffic distribution report ─────────────────────────────────
    def print_stats(self):
        total = sum(self.stats.values()) or 1
        self.logger.info("=" * 50)
        self.logger.info("  TRAFFIC CLASSIFICATION REPORT")
        self.logger.info("=" * 50)
        for proto in ["TCP", "UDP", "ICMP", "Other"]:
            count = self.stats[proto]
            pct   = (count / total) * 100
            bar   = "#" * int(pct / 5)
            self.logger.info(
                "  %-6s: %4d packets (%5.1f%%) %s",
                proto, count, pct, bar)
        self.logger.info("  Total : %d packets", total)
        self.logger.info("=" * 50)
