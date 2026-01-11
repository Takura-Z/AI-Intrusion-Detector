import scapy.all as scapy
import pandas as pd
import numpy as np
from collections import OrderedDict

class NetworkFlow:
    def __init__(self, start_time, ip_src, ip_dst, src_port, dst_port, protocol, is_forward_direction):
        self.flow_key = (ip_src, ip_dst, src_port, dst_port, protocol)
        self.is_forward_direction = is_forward_direction
        self.start_time = float(start_time)
        self.end_time = float(start_time)
        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.total_byte_count = 0
        self.fwd_byte_count = 0
        self.bwd_byte_count = 0
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.all_packet_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.last_fwd_timestamp = float(start_time)
        self.last_bwd_timestamp = float(start_time)
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1
        self.flow_syn_count = 0
        self.flow_ack_count = 0
        self.flow_fin_count = 0
        self.flow_psh_count = 0
        self.flow_urg_count = 0
        self.flow_ece_count = 0
        self.flow_cwr_count = 0
        self.active_times = []
        self.idle_times = []
        self.last_timestamp = float(start_time)
        self.packet_count_in_flow = 0

    def add_packet(self, packet, current_time):
        current_time = float(current_time)
        self.end_time = current_time
        self.packet_count_in_flow += 1
        
        if self.packet_count_in_flow > 1:
            time_since_last_packet = current_time - self.last_timestamp
            if time_since_last_packet > 1.0:
                self.idle_times.append(time_since_last_packet)
                self.active_times.append(0)
            else:
                if self.active_times: self.active_times[-1] += time_since_last_packet
                else: self.active_times.append(time_since_last_packet)
        
        self.last_timestamp = current_time
        packet_size = len(packet)
        self.all_packet_lengths.append(packet_size)
        self.total_byte_count += packet_size
        
        is_packet_forward = (packet[scapy.IP].src, packet[scapy.IP].dst) == self.is_forward_direction
        
        if is_packet_forward:
            self.fwd_packet_count += 1
            self.fwd_byte_count += packet_size
            self.fwd_packet_lengths.append(packet_size)
            if self.fwd_packet_count > 1: self.fwd_iat.append(current_time - self.last_fwd_timestamp)
            self.last_fwd_timestamp = current_time
        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += packet_size
            self.bwd_packet_lengths.append(packet_size)
            if self.bwd_packet_count > 1: self.bwd_iat.append(current_time - self.last_bwd_timestamp)
            self.last_bwd_timestamp = current_time

        if scapy.TCP in packet:
            header_len = packet[scapy.TCP].dataofs * 4
            if is_packet_forward:
                self.fwd_header_length += header_len
                if self.init_win_bytes_fwd == -1: self.init_win_bytes_fwd = packet[scapy.TCP].window
            else:
                self.bwd_header_length += header_len
                if self.init_win_bytes_bwd == -1: self.init_win_bytes_bwd = packet[scapy.TCP].window
            
            flags = packet[scapy.TCP].flags
            if 'S' in flags: self.flow_syn_count += 1
            if 'A' in flags: self.flow_ack_count += 1
            if 'F' in flags: self.flow_fin_count += 1
            if 'P' in flags: self.flow_psh_count += 1
            if 'U' in flags: self.flow_urg_count += 1
            if 'E' in flags: self.flow_ece_count += 1
            if 'C' in flags: self.flow_cwr_count += 1

    def get_features(self):
        duration = self.end_time - self.start_time
        fwd_iat_mean = np.mean(self.fwd_iat) if self.fwd_iat else 0
        bwd_iat_mean = np.mean(self.bwd_iat) if self.bwd_iat else 0
        all_iat = self.fwd_iat + self.bwd_iat
        flow_iat_mean = np.mean(all_iat) if all_iat else 0
        
        fwd_pkt_len_mean = np.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        bwd_pkt_len_mean = np.mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        all_pkt_len_mean = np.mean(self.all_packet_lengths) if self.all_packet_lengths else 0

        features = OrderedDict()
        features['Destination Port'] = self.flow_key[3]
        features['Flow Duration'] = duration
        features['Total Fwd Packets'] = self.fwd_packet_count
        features['Total Backward Packets'] = self.bwd_packet_count
        features['Total Length of Fwd Packets'] = self.fwd_byte_count
        features['Total Length of Bwd Packets'] = self.bwd_byte_count
        features['Fwd Packet Length Max'] = max(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        features['Fwd Packet Length Min'] = min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        features['Fwd Packet Length Mean'] = fwd_pkt_len_mean
        features['Fwd Packet Length Std'] = np.std(self.fwd_packet_lengths) if len(self.fwd_packet_lengths) > 1 else 0
        features['Bwd Packet Length Max'] = max(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        features['Bwd Packet Length Min'] = min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        features['Bwd Packet Length Mean'] = bwd_pkt_len_mean
        features['Bwd Packet Length Std'] = np.std(self.bwd_packet_lengths) if len(self.bwd_packet_lengths) > 1 else 0
        features['Flow Bytes/s'] = self.total_byte_count / duration if duration > 0 else 0
        features['Flow Packets/s'] = (self.fwd_packet_count + self.bwd_packet_count) / duration if duration > 0 else 0
        features['Flow IAT Mean'] = flow_iat_mean
        features['Flow IAT Std'] = np.std(all_iat) if len(all_iat) > 1 else 0
        features['Flow IAT Max'] = max(all_iat) if all_iat else 0
        features['Flow IAT Min'] = min(all_iat) if all_iat else 0
        features['Fwd IAT Total'] = sum(self.fwd_iat)
        features['Fwd IAT Mean'] = fwd_iat_mean
        features['Fwd IAT Std'] = np.std(self.fwd_iat) if len(self.fwd_iat) > 1 else 0
        features['Fwd IAT Max'] = max(self.fwd_iat) if self.fwd_iat else 0
        features['Fwd IAT Min'] = min(self.fwd_iat) if self.fwd_iat else 0
        features['Bwd IAT Total'] = sum(self.bwd_iat)
        features['Bwd IAT Mean'] = bwd_iat_mean
        features['Bwd IAT Std'] = np.std(self.bwd_iat) if len(self.bwd_iat) > 1 else 0
        features['Bwd IAT Max'] = max(self.bwd_iat) if self.bwd_iat else 0
        features['Bwd IAT Min'] = min(self.bwd_iat) if self.bwd_iat else 0
        features['Fwd PSH Flags'] = self.flow_psh_count
        features['Bwd PSH Flags'] = 0
        features['Fwd URG Flags'] = self.flow_urg_count
        features['Bwd URG Flags'] = 0
        features['Fwd Header Length'] = self.fwd_header_length
        features['Bwd Header Length'] = self.bwd_header_length
        features['Fwd Packets/s'] = self.fwd_packet_count / duration if duration > 0 else 0
        features['Bwd Packets/s'] = self.bwd_packet_count / duration if duration > 0 else 0
        features['Min Packet Length'] = min(self.all_packet_lengths) if self.all_packet_lengths else 0
        features['Max Packet Length'] = max(self.all_packet_lengths) if self.all_packet_lengths else 0
        features['Packet Length Mean'] = all_pkt_len_mean
        features['Packet Length Std'] = np.std(self.all_packet_lengths) if len(self.all_packet_lengths) > 1 else 0
        features['Packet Length Variance'] = np.var(self.all_packet_lengths) if len(self.all_packet_lengths) > 1 else 0
        features['FIN Flag Count'] = self.flow_fin_count
        features['SYN Flag Count'] = self.flow_syn_count
        features['RST Flag Count'] = 0 
        features['PSH Flag Count'] = self.flow_psh_count
        features['ACK Flag Count'] = self.flow_ack_count
        features['URG Flag Count'] = self.flow_urg_count
        features['CWE Flag Count'] = self.flow_cwr_count
        features['ECE Flag Count'] = self.flow_ece_count
        features['Down/Up Ratio'] = self.bwd_packet_count / self.fwd_packet_count if self.fwd_packet_count > 0 else 0
        features['Average Packet Size'] = all_pkt_len_mean
        features['Avg Fwd Segment Size'] = fwd_pkt_len_mean
        features['Avg Bwd Segment Size'] = bwd_pkt_len_mean
        # --- FEATURE 56: THE DUPLICATE ---
        features['Fwd Header Length.1'] = self.fwd_header_length 
        features['Fwd Avg Bytes/Bulk'] = 0
        features['Fwd Avg Packets/Bulk'] = 0
        features['Fwd Avg Bulk Rate'] = 0
        features['Bwd Avg Bytes/Bulk'] = 0
        features['Bwd Avg Packets/Bulk'] = 0
        features['Bwd Avg Bulk Rate'] = 0
        features['Subflow Fwd Packets'] = self.fwd_packet_count
        features['Subflow Fwd Bytes'] = self.fwd_byte_count
        features['Subflow Bwd Packets'] = self.bwd_packet_count
        features['Subflow Bwd Bytes'] = self.bwd_byte_count
        features['Init_Win_bytes_forward'] = self.init_win_bytes_fwd
        features['Init_Win_bytes_backward'] = self.init_win_bytes_bwd
        features['act_data_pkt_fwd'] = self.fwd_packet_count
        features['min_seg_size_forward'] = min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        features['Active Mean'] = np.mean(self.active_times) if self.active_times else 0
        features['Active Std'] = np.std(self.active_times) if len(self.active_times) > 1 else 0
        features['Active Max'] = max(self.active_times) if self.active_times else 0
        features['Active Min'] = min(self.active_times) if self.active_times else 0
        features['Idle Mean'] = np.mean(self.idle_times) if self.idle_times else 0
        features['Idle Std'] = np.std(self.idle_times) if len(self.idle_times) > 1 else 0
        features['Idle Max'] = max(self.idle_times) if self.idle_times else 0
        features['Idle Min'] = min(self.idle_times) if self.idle_times else 0
        
        return features

def extract_features_from_pcap(file_path):
    flows = {}
    packets = scapy.PcapReader(file_path)
    for packet in packets:
        if not packet.haslayer(scapy.IP): continue
        ip_src, ip_dst = packet[scapy.IP].src, packet[scapy.IP].dst
        if packet.haslayer(scapy.TCP):
            protocol, src_port, dst_port = 'TCP', packet[scapy.TCP].sport, packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            protocol, src_port, dst_port = 'UDP', packet[scapy.UDP].sport, packet[scapy.UDP].dport
        else: continue
        key = (ip_dst, ip_src, dst_port, src_port, protocol) if ip_src > ip_dst else (ip_src, ip_dst, src_port, dst_port, protocol)
        fwd_dir = (ip_src, ip_dst)
        if key not in flows:
            flows[key] = NetworkFlow(packet.time, ip_src, ip_dst, src_port, dst_port, protocol, fwd_dir)
        flows[key].add_packet(packet, packet.time)
        
    return pd.DataFrame([f.get_features() for f in flows.values()])