#!/usr/bin/env python3
"""
# Rewrite an existing GTP-U PCAP while preserving packet count/size:
python3 gtpu_editor.py \
  --in pktgen-dpdk/pcap/gtpv1-u-1024.pcap \
  --out pktgen-dpdk/pcap/gtpv1-u-1024-modified.pcap \
  --outer-src-mac 90:e2:ba:b3:74:b0 \
  --outer-dst-mac 90:e2:ba:b2:92:5c \
  --outer-src-ip 10.10.1.1 \
  --outer-dst-ip 10.10.1.2 \
  --inner-src-ip 10.60.0.1 \
  --inner-dst-ip 192.168.1.4 \
  --teid 0x1 \
  --gtpu-type 255

# Generate uplink GTP-U packets for two UE sessions:
python3 gtpu_editor.py \
  --generate \
  --out pktgen-dpdk/pcap/upf-lb-2ue.pcap \
  --count 1000 \
  --packet-size 1024 \
  --outer-src-mac 22:b4:ba:4f:46:b8 \
  --outer-dst-mac 2a:a2:c3:d0:c2:93 \
  --outer-src-ip 192.168.2.1 \
  --outer-dst-ip 192.168.2.2 \
  --inner-dst-ip 192.168.3.2 \
  --flows 10.60.0.1:2,10.60.0.2:6

# Generate downlink plain IP packets from DN to two UEs:
python3 gtpu_editor.py \
  --generate \
  --plain-ip \
  --out pktgen-dpdk/pcap/downlink-2ue.pcap \
  --count 1000 \
  --packet-size 1024 \
  --outer-src-mac 2e:4a:d2:32:15:c1 \
  --outer-dst-mac 22:fe:af:8d:c7:43 \
  --outer-src-ip 192.168.3.2 \
  --outer-dst-ip 192.168.3.1 \
  --inner-dst-ip 10.60.0.1 \
  --plain-flows 192.168.3.2:10.60.0.1,192.168.3.2:10.60.0.2
"""

import argparse
from scapy.all import Raw, rdpcap, wrpcap, Ether, IP, UDP
from scapy.contrib.gtp import GTP_U_Header


def parse_flows(flow_spec):
    flows = []
    if not flow_spec:
        return flows

    for item in flow_spec.split(","):
        item = item.strip()
        if not item:
            continue
        ue_ip, teid = item.split(":", 1)
        flows.append((ue_ip.strip(), int(teid.strip(), 0)))

    return flows


def parse_plain_flows(flow_spec):
    flows = []
    if not flow_spec:
        return flows

    for item in flow_spec.split(","):
        item = item.strip()
        if not item:
            continue
        src_ip, dst_ip = item.split(":", 1)
        flows.append((src_ip.strip(), dst_ip.strip()))

    return flows


def build_gtpu_packet(args, index, flow):
    inner_src_ip, teid = flow
    inner_sport = args.inner_src_port if args.inner_src_port is not None else 1234
    inner_dport = args.inner_dst_port if args.inner_dst_port is not None else 5201
    outer_sport = args.outer_src_port if args.outer_src_port is not None else 2152
    outer_dport = args.outer_dst_port if args.outer_dst_port is not None else 2152

    payload_size = args.payload_size
    if args.packet_size is not None:
        header_len = 14 + 20 + 8 + 8 + 20 + 8
        payload_size = args.packet_size - header_len
        if payload_size < 0:
            raise ValueError(f"--packet-size must be at least {header_len} bytes")

    payload = bytes([(index + i) & 0xff for i in range(payload_size)])

    inner = (
        IP(src=inner_src_ip, dst=args.inner_dst_ip)
        / UDP(sport=inner_sport, dport=inner_dport)
        / Raw(payload)
    )

    return (
        Ether(src=args.outer_src_mac, dst=args.outer_dst_mac)
        / IP(src=args.outer_src_ip, dst=args.outer_dst_ip)
        / UDP(sport=outer_sport, dport=outer_dport)
        / GTP_U_Header(gtp_type=args.gtpu_type, teid=teid)
        / inner
    )


def build_plain_ip_packet(args, index, flow):
    inner_src_ip, inner_dst_ip = flow
    inner_sport = args.inner_src_port if args.inner_src_port is not None else 1234
    inner_dport = args.inner_dst_port if args.inner_dst_port is not None else 5201

    payload_size = args.payload_size
    if args.packet_size is not None:
        header_len = 14 + 20 + 8
        payload_size = args.packet_size - header_len
        if payload_size < 0:
            raise ValueError(f"--packet-size must be at least {header_len} bytes")

    payload = bytes([(index + i) & 0xff for i in range(payload_size)])

    return (
        Ether(src=args.outer_src_mac, dst=args.outer_dst_mac)
        / IP(src=inner_src_ip, dst=inner_dst_ip)
        / UDP(sport=inner_sport, dport=inner_dport)
        / Raw(payload)
    )


def rewrite_gtpu_packet(pkt, args):
    """
    Rewrite outer MAC/IP/UDP, inner MAC/IP/UDP, and GTP-U header fields.
    """
    # Must be GTP-U over UDP/2152 (match BEFORE changing ports)
    if not (UDP in pkt and pkt[UDP].dport == 2152 and GTP_U_Header in pkt):
        return pkt

    # ---------- Outer Ethernet ----------
    if Ether in pkt and args.outer_src_mac and args.outer_dst_mac:
        pkt[Ether].src = args.outer_src_mac
        pkt[Ether].dst = args.outer_dst_mac

    # ---------- Outer IP ----------
    if IP in pkt and args.outer_src_ip and args.outer_dst_ip:
        pkt[IP].src = args.outer_src_ip
        pkt[IP].dst = args.outer_dst_ip
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum

    # ---------- Outer UDP (GTP-U UDP header) ----------
    if UDP in pkt:
        if args.outer_src_port is not None:
            pkt[UDP].sport = args.outer_src_port
        if args.outer_dst_port is not None:
            pkt[UDP].dport = args.outer_dst_port
        if hasattr(pkt[UDP], "len"):
            del pkt[UDP].len
        if hasattr(pkt[UDP], "chksum"):
            del pkt[UDP].chksum

    # ---------- GTP-U Header ----------
    gtp = pkt[GTP_U_Header]
    if args.teid is not None:
        gtp.teid = args.teid
    if args.gtpu_type is not None:
        gtp.gtp_type = args.gtpu_type

    # ---------- Inner payload (inside GTP-U) ----------
    inner = gtp.payload

    # Inner Ethernet
    if Ether in inner and args.inner_src_mac and args.inner_dst_mac:
        inner[Ether].src = args.inner_src_mac
        inner[Ether].dst = args.inner_dst_mac

    # Inner IP
    if IP in inner and args.inner_src_ip and args.inner_dst_ip:
        inner[IP].src = args.inner_src_ip
        inner[IP].dst = args.inner_dst_ip
        if hasattr(inner[IP], "len"):
            del inner[IP].len
        if hasattr(inner[IP], "chksum"):
            del inner[IP].chksum

    # Inner UDP (user-plane flow)
    if UDP in inner:
        if args.inner_src_port is not None:
            inner[UDP].sport = args.inner_src_port
        if args.inner_dst_port is not None:
            inner[UDP].dport = args.inner_dst_port
        if hasattr(inner[UDP], "len"):
            del inner[UDP].len
        if hasattr(inner[UDP], "chksum"):
            del inner[UDP].chksum

    return pkt


def main():
    parser = argparse.ArgumentParser(description="Generate or rewrite GTP-U PCAP files")

    # Input/output
    parser.add_argument("--generate", action="store_true", help="Generate a new PCAP instead of rewriting an input PCAP")
    parser.add_argument("--plain-ip", action="store_true", help="Generate plain Ethernet/IP/UDP packets instead of GTP-U")
    parser.add_argument("--in", dest="in_pcap", help="Input PCAP file")
    parser.add_argument("--out", dest="out_pcap", required=True, help="Output PCAP file")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to generate")
    parser.add_argument("--payload-size", type=int, default=1024, help="Generated inner UDP payload size in bytes")
    parser.add_argument("--packet-size", type=int, help="Generated Ethernet frame size in bytes, excluding FCS")
    parser.add_argument("--flows", help="Generated flows as UE_IP:TEID[,UE_IP:TEID], e.g. 10.60.0.1:2,10.60.0.2:6")
    parser.add_argument("--plain-flows", help="Generated plain-IP flows as SRC_IP:DST_IP[,SRC_IP:DST_IP]")

    # Outer L2/L3
    parser.add_argument("--outer-src-mac", required=True)
    parser.add_argument("--outer-dst-mac", required=True)
    parser.add_argument("--outer-src-ip", required=True)
    parser.add_argument("--outer-dst-ip", required=True)

    # Outer UDP ports (GTP-U UDP)
    parser.add_argument("--outer-src-port", type=int, required=False,
                        help="Outer UDP source port (default: keep original)")
    parser.add_argument("--outer-dst-port", type=int, required=False,
                        help="Outer UDP dest port (default: keep original)")

    # Inner L2/L3
    parser.add_argument("--inner-src-mac", required=False)
    parser.add_argument("--inner-dst-mac", required=False)
    parser.add_argument("--inner-src-ip")
    parser.add_argument("--inner-dst-ip", required=True)

    # Inner UDP ports (user traffic)
    parser.add_argument("--inner-src-port", type=int, required=False,
                        help="Inner UDP source port (default: keep original)")
    parser.add_argument("--inner-dst-port", type=int, required=False,
                        help="Inner UDP dest port (default: keep original)")

    # GTP-U header fields
    parser.add_argument("--teid", type=lambda x: int(x, 0),
                        help="New TEID (decimal or hex, e.g., 0x1234)")
    parser.add_argument("--gtpu-type", dest="gtpu_type", type=int, default=255,
                        help="GTP-U Message Type (e.g., 255 for G-PDU)")

    args = parser.parse_args()
    flows = parse_flows(args.flows)
    plain_flows = parse_plain_flows(args.plain_flows)

    if args.generate:
        if args.plain_ip:
            if plain_flows:
                flows = plain_flows
            elif not flows:
                if args.inner_src_ip is None:
                    parser.error("--generate --plain-ip requires --plain-flows, --flows, or --inner-src-ip")
                flows = [(args.inner_src_ip, args.inner_dst_ip)]
            else:
                flows = [(src_ip, args.inner_dst_ip) for src_ip, _ in flows]
        elif not flows:
            if args.inner_src_ip is None or args.teid is None:
                parser.error("--generate requires either --flows or both --inner-src-ip and --teid")
            flows = [(args.inner_src_ip, args.teid)]

        if not flows:
            if args.plain_ip:
                parser.error("--generate --plain-ip has no flows")
            else:
                parser.error("--generate has no flows")

        packet_type = "plain IP" if args.plain_ip else "GTP-U"
        builder = build_plain_ip_packet if args.plain_ip else build_gtpu_packet
        print(f"[*] Generating {args.count} {packet_type} packets")
        packets = [builder(args, i, flows[i % len(flows)]) for i in range(args.count)]
        print(f"[*] Writing {args.out_pcap}")
        wrpcap(args.out_pcap, packets)
        return

    if not args.in_pcap:
        parser.error("--in is required unless --generate is used")

    print(f"[*] Reading {args.in_pcap}")
    packets = rdpcap(args.in_pcap)

    new_packets = []
    modified = 0

    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 2152 and GTP_U_Header in pkt:
            modified += 1
        new_packets.append(rewrite_gtpu_packet(pkt, args))

    print(f"[*] Modified {modified} GTP-U packets")
    print(f"[*] Writing {args.out_pcap}")
    wrpcap(args.out_pcap, new_packets)


if __name__ == "__main__":
    main()
