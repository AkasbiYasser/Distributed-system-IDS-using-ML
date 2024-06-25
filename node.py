import pandas as pd
import socket
import threading
import time
import os
import signal
import subprocess
from scapy.all import sniff, TCP, UDP, ICMP, IP
from collections import defaultdict
import telegram
class PacketSniffer:
    def __init__(self):
        self.columns_to_extract = [
            "Duration", "Protocol_type", "Service", "Flag", "Src_bytes", "Dst_bytes",
            "Wrong_fragment", "Hot", "Logged_in", "Num_compromised", "Root_shell",
            "Su_attempted", "Num_root", "Num_file_creations", "Num_shells",
            "Num_access_files", "Is_hot_login", "Is_guest_login", "Count", "Srv_count",
            "Serror_rate", "Srv_serror_rate", "Rerror_rate", "Srv_rerror_rate",
            "Same_srv_rate", "Diff_srv_rate", "Srv_diff_host_rate", "Dst_host_count",
            "Dst_host_srv_count", "Dst_host_same_srv_rate", "Dst_host_diff_srv_rate",
            "Dst_host_same_src_port_rate", "Dst_host_srv_diff_host_rate",
            "Dst_host_serror_rate", "Dst_host_srv_serror_rate", "Dst_host_rerror_rate",
            "Dst_host_srv_rerror_rate"
        ]

        self.port_to_service = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
            80: 'http', 110: 'pop_3', 143: 'imap4', 443: 'http_443', 993: 'imap4', 995: 'pop_3',
        }

        self.tcp_flags_mapping = {
            'S': 'SF', 'SA': 'SF', 'R': 'REJ', 'RA': 'RSTR', 'F': 'SH', 'FA': 'SH', 'RFA': 'RSTO',
            'SFA': 'S1', 'RS': 'RSTOS0', 'FPA': 'S3', 'PA': 'S2', '': 'OTH'
        }

        self.active_connections = {}
        self.connection_start_times = {}
        self.connection_count = defaultdict(int)
        self.service_count = defaultdict(int)
        self.captured_packets = []
        self.packet_number = 0

    def get_service(self, packet):
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return 'other'
        return self.port_to_service.get(dport, 'other')

    def get_flag(self, packet):
        if TCP in packet:
            flags = packet.sprintf('%TCP.flags%')
            return self.tcp_flags_mapping.get(flags, 'OTH')
        return 0

    def get_connection_id(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = '0.0.0.0'
            dst = '0.0.0.0'
        sport = packet.sport if (TCP in packet or UDP in packet) else 0
        dport = packet.dport if (TCP in packet or UDP in packet) else 0
        return (src, dst, sport, dport)

    def process_packet(self, packet):
        self.packet_number += 1
        print(f"We are processing packet number {self.packet_number}")
        packet_data = {}
        connection_id = self.get_connection_id(packet)
        if IP in packet:
            packet_data["Protocol_type"] = 'tcp' if TCP in packet else 'udp' if UDP in packet else 'icmp' if ICMP in packet else 0
            packet_data["Service"] = self.get_service(packet)
            packet_data["Flag"] = self.get_flag(packet)
            if TCP in packet:
                packet_data["Src_bytes"] = len(packet[TCP].payload)
                packet_data["Dst_bytes"] = len(packet[TCP].payload)
            elif UDP in packet:
                packet_data["Src_bytes"] = len(packet[UDP].payload)
                packet_data["Dst_bytes"] = len(packet[UDP].payload)
            else:
                packet_data["Src_bytes"] = 0
                packet_data["Dst_bytes"] = 0
            packet_data["Wrong_fragment"] = packet[IP].frag
            packet_data["Hot"] = 1 if "cd /" in str(packet[IP].payload) or "chmod " in str(packet[IP].payload) else 0
            packet_data["Logged_in"] = 1 if "login" in str(packet[IP].payload) else 0
            packet_data["Num_compromised"] = 0
            packet_data["Root_shell"] = 0
            packet_data["Su_attempted"] = 0
            packet_data["Num_root"] = 0
            packet_data["Num_file_creations"] = 0
            packet_data["Num_shells"] = 0
            packet_data["Num_access_files"] = 0
            packet_data["Is_hot_login"] = 0
            packet_data["Is_guest_login"] = 0
            if connection_id not in self.connection_start_times:
                self.connection_start_times[connection_id] = time.time()
                self.active_connections[connection_id] = []
            packet_data["Duration"] = round(time.time() - self.connection_start_times[connection_id], 2)
            self.active_connections[connection_id].append(packet)
            src_dst_pair = (packet[IP].src, packet[IP].dst)
            service_pair = (packet[IP].src, packet[IP].dst, packet.sport if (TCP in packet or UDP in packet) else 0, packet.dport if (TCP in packet or UDP in packet) else 0)
            self.connection_count[src_dst_pair] += 1
            self.service_count[service_pair] += 1
            packet_data["Count"] = self.connection_count[src_dst_pair]
            packet_data["Srv_count"] = self.service_count[service_pair]
            error_flags = ['REJ', 'RSTO', 'RSTOS0', 'RSTR']
            serror_flags = ['S0', 'S1', 'S2', 'S3']
            all_flags = [self.get_flag(p) for p in self.active_connections[connection_id]]
            error_count = sum(flag in error_flags for flag in all_flags)
            serror_count = sum(flag in serror_flags for flag in all_flags)
            packet_data["Serror_rate"] = serror_count / len(all_flags) if len(all_flags) > 0 else  0
            packet_data["Srv_serror_rate"] = serror_count / len(all_flags) if len(all_flags) > 0 else 0
            packet_data["Rerror_rate"] = error_count / len(all_flags) if len(all_flags) > 0 else 0
            packet_data["Srv_rerror_rate"] = error_count / len(all_flags) if len(all_flags) > 0 else 0
            packet_data["Same_srv_rate"] = self.service_count[service_pair] / self.connection_count[src_dst_pair] if self.connection_count[src_dst_pair] > 0 else 0
            packet_data["Diff_srv_rate"] = 1 - packet_data["Same_srv_rate"]
            return packet_data

    def packet_callback(self, packet):
        try:
            packet_data = self.process_packet(packet)
            if packet_data:
                self.captured_packets.append(packet_data)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_sniffing(self):
        try:
            sniff(prn=self.packet_callback, count=100, filter="ip host 10.0.0.1", iface="ens37")
            self.save_data()
            os.kill(os.getpid(), signal.SIGUSR1)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    def save_data(self):
        try:
            df = pd.DataFrame(self.captured_packets)
            
            for column in self.columns_to_extract:
                if column not in df.columns:
                    df[column] = 0
            df = df[self.columns_to_extract]
            df = df.fillna(0)
            df.to_csv('extracted_packets.csv', index=False, header=False)
        except Exception as e:
            print(f"Error saving data: {e}")

def send_message(message):
    host = '157.173.199.241'
    port = 9001
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.sendall(message.encode())
    response = client_socket.recv(1024).decode()
    client_socket.close()
    return response

def cmd(command):
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return str(e)

def scp_file():
    try:
        scp_command = "sshpass -p '1' scp extracted_packets.csv hamza@157.173.199.241:/home/hamza"
        result = cmd(scp_command)
        print(f"SCP result: {result}")
    except Exception as e:
        print(f"Error in SCP file transfer: {e}")

def signal_handler(signum, frame):
    try:
        scp_file()
        response = send_message("verify")
        if response == "attack":
            print("An attack detected")
            telegram.send_telegram_message("An Attack Detectedd!!!")
            telegram.main()
        else:
            print("No attack detected")
    except Exception as e:
        print(f"Error in signal handler: {e}")

def main():
    try:
        sniffer = PacketSniffer()
        signal.signal(signal.SIGUSR1, signal_handler)
        sniffing_thread = threading.Thread(target=sniffer.start_sniffing)
        sniffing_thread.start()
        sniffing_thread.join()
    except Exception as e:
        print(f"Error in main: {e}")

while True:
    main()
