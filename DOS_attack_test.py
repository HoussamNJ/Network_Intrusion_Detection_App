# port_scan.py
from scapy.all import *
import sys

# --- Configuration ---
TARGET_IP = "192.168.192.67" # <--- REMPLACEZ PAR L'IP DE VOTRE MACHINE
MIN_PORT = 1
MAX_PORT = 3036
# ---------------------

if not TARGET_IP or TARGET_IP == "YOUR_MACHINE_IP":
    print("[!] Erreur : Veuillez définir la variable TARGET_IP.")
    sys.exit(1)

print(f"[*] Lancement du balayage de ports sur {TARGET_IP} de {MIN_PORT} à {MAX_PORT}")

open_ports = []
for port in range(MIN_PORT, MAX_PORT + 1):
    # Envoi d'un paquet SYN (demande de connexion)
    response = sr1(IP(dst=TARGET_IP)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
    
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: # SYN-ACK
        # Le port est ouvert
        open_ports.append(port)
        print(f"[+] Port {port} est ouvert.")
        # Envoi d'un paquet RST pour fermer la connexion proprement
        send(IP(dst=TARGET_IP)/TCP(dport=port, flags="R"), verbose=0)
    else:
        print(f"[-] Port {port} est fermé ou filtré.")

print(f"\n[*] Balayage terminé. Ports ouverts trouvés : {open_ports}")