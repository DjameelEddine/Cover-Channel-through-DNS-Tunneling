#!/usr/bin/env python3
"""
DNS Packet Sniffer with ML Detection
Captures DNS queries, extracts features, and detects malicious DNS using pre-trained model.
"""

import sys
import pickle
import csv
import math
import argparse
import warnings
import numpy as np
from collections import defaultdict, Counter
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from datetime import datetime

# Suppress sklearn version mismatch warnings
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')


class DNSAnalyzer:
    """Extract features and predict malicious DNS queries."""
    
    def __init__(self, model_path="model.pkl"):
        """Initialize analyzer with model."""
        self.model = self.load_model(model_path)
        self.csv_file = "dns_analysis.csv"
        self.packet_count = 0
        self.init_csv()
    
    def load_model(self, model_path):
        """Load pre-trained model."""
        try:
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            print(f"ERROR: Model file {model_path} not found!", file=sys.stderr)
            sys.exit(1)
    
    def init_csv(self):
        """Initialize CSV file."""
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Flow', 'Timestamp', 'Source IP', 'Destination IP', 'Source Port', 
                'Destination Port', 'Domain', 'Packet Count', 'Duration(s)', 
                'Bytes Sent', 'Prediction', 'Confidence'
            ])
    
    def predict(self, features_dict):
        """Predict if flow is malicious.
        
        Args:
            features_dict: Dictionary with 34 feature values
        
        Returns:
            (prediction, confidence)
        """
        try:
            with open('label_encoder.pkl', 'rb') as f:
                label_encoder = pickle.load(f)
            with open('scaler.pkl', 'rb') as f:
                scaler = pickle.load(f)
            
            # Feature ordering (must match model training)
            feature_order = [
                'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort',
                'TimeStamp', 'Duration', 'FlowBytesSent', 'FlowSentRate',
                'FlowBytesReceived', 'FlowReceivedRate', 'PacketLengthVariance',
                'PacketLengthStandardDeviation', 'PacketLengthMean', 'PacketLengthMedian',
                'PacketLengthMode', 'PacketLengthSkewFromMedian', 'PacketLengthSkewFromMode',
                'PacketLengthCoefficientofVariation', 'PacketTimeVariance',
                'PacketTimeStandardDeviation', 'PacketTimeMean', 'PacketTimeMedian',
                'PacketTimeMode', 'PacketTimeSkewFromMedian', 'PacketTimeSkewFromMode',
                'PacketTimeCoefficientofVariation', 'ResponseTimeTimeVariance',
                'ResponseTimeTimeStandardDeviation', 'ResponseTimeTimeMean',
                'ResponseTimeTimeMedian', 'ResponseTimeTimeMode',
                'ResponseTimeTimeSkewFromMedian', 'ResponseTimeTimeSkewFromMode',
                'ResponseTimeTimeCoefficientofVariation'
            ]
            
            # Build feature array, converting numpy types to native Python types
            features = []
            for k in feature_order:
                val = features_dict[k]
                # Convert numpy types to native Python types
                if isinstance(val, np.generic):
                    val = val.item()
                features.append(val)
            
            features = [features]
            
            # Apply label encoder to first 4 features (IPs and Ports) - ensure they are native strings
            for i in range(4):
                features[0][i] = label_encoder.transform([str(features[0][i])])[0]
            
            # Convert all features to float for scaler
            features = [[float(f) for f in features[0]]]
            
            # Apply scaler to all features
            scaled = scaler.transform(features)
            
            pred = self.model.predict(scaled)[0]
            prob = max(self.model.predict_proba(scaled)[0])
            
            return pred, prob
        except Exception as e:
            print(f"Prediction error: {e}", file=sys.stderr)
            return 0, 0.0


class DNSSniffer:
    """Captures DNS packets, aggregates into flows, and detects malicious flows."""
    
    def __init__(self, packet_count=0, interface=None):
        """Initialize sniffer."""
        self.packet_count = packet_count
        self.interface = interface
        self.packet_num = 0
        self.flow_num = 0
        self.analyzer = DNSAnalyzer()
        self.flows = defaultdict(lambda: {
            'packets': [],
            'packet_sizes': [],
            'packet_times': [],
            'response_times': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': None,
            'domains': []
        })
    
    @staticmethod
    def calc_statistics(values):
        """Calculate statistics for a list of values."""
        if not values:
            return 0, 0, 0, 0, 0, 0, 0, 0
        
        values = sorted(values)
        n = len(values)
        mean = sum(values) / n
        median = values[n//2] if n % 2 else (values[n//2-1] + values[n//2]) / 2
        mode = Counter(values).most_common(1)[0][0]
        variance = sum((x - mean) ** 2 for x in values) / n
        std_dev = math.sqrt(variance)
        skew_median = sum((x - median) for x in values) / n
        skew_mode = sum((x - mode) for x in values) / n
        coeff_var = (std_dev / mean) if mean != 0 else 0
        
        return variance, std_dev, mean, median, mode, skew_median, skew_mode, coeff_var
    
    def get_flow_key(self, packet):
        """Extract flow identifier from packet."""
        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"
            src_port = packet[UDP].sport if packet.haslayer(UDP) else 0
            dst_port = packet[UDP].dport if packet.haslayer(UDP) else 53
            return (src_ip, dst_ip, src_port, dst_port)
        except:
            return None
    
    def analyze_flow(self, flow_key, flow_data):
        """Analyze a complete flow and make prediction."""
        self.flow_num += 1
        src_ip, dst_ip, src_port, dst_port = flow_key
        
        current_time = datetime.now().timestamp()
        
        # Calculate statistics
        pkt_sizes = flow_data['packet_sizes']
        pkt_times = flow_data['packet_times']
        resp_times = flow_data['response_times']
        
        pkt_len_var, pkt_len_std, pkt_len_mean, pkt_len_median, pkt_len_mode, \
            pkt_len_skew_median, pkt_len_skew_mode, pkt_len_coeff_var = self.calc_statistics(pkt_sizes)
        
        pkt_time_var, pkt_time_std, pkt_time_mean, pkt_time_median, pkt_time_mode, \
            pkt_time_skew_median, pkt_time_skew_mode, pkt_time_coeff_var = self.calc_statistics(pkt_times)
        
        resp_time_var, resp_time_std, resp_time_mean, resp_time_median, resp_time_mode, \
            resp_time_skew_median, resp_time_skew_mode, resp_time_coeff_var = self.calc_statistics(resp_times)
        
        # Flow duration and rates
        duration = current_time - flow_data['start_time'] if flow_data['start_time'] else 1
        duration = max(duration, 0.001)
        
        sent_rate = flow_data['bytes_sent'] / duration
        received_rate = flow_data['bytes_received'] / duration
        
        domain = flow_data['domains'][0] if flow_data['domains'] else ""
        
        # Build feature dictionary
        features = {
            'SourceIP': src_ip,
            'DestinationIP': dst_ip,
            'SourcePort': src_port,
            'DestinationPort': dst_port,
            'TimeStamp': flow_data['start_time'],
            'Duration': duration,
            'FlowBytesSent': flow_data['bytes_sent'],
            'FlowSentRate': sent_rate,
            'FlowBytesReceived': flow_data['bytes_received'],
            'FlowReceivedRate': received_rate,
            'PacketLengthVariance': pkt_len_var,
            'PacketLengthStandardDeviation': pkt_len_std,
            'PacketLengthMean': pkt_len_mean,
            'PacketLengthMedian': pkt_len_median,
            'PacketLengthMode': pkt_len_mode,
            'PacketLengthSkewFromMedian': pkt_len_skew_median,
            'PacketLengthSkewFromMode': pkt_len_skew_mode,
            'PacketLengthCoefficientofVariation': pkt_len_coeff_var,
            'PacketTimeVariance': pkt_time_var,
            'PacketTimeStandardDeviation': pkt_time_std,
            'PacketTimeMean': pkt_time_mean,
            'PacketTimeMedian': pkt_time_median,
            'PacketTimeMode': pkt_time_mode,
            'PacketTimeSkewFromMedian': pkt_time_skew_median,
            'PacketTimeSkewFromMode': pkt_time_skew_mode,
            'PacketTimeCoefficientofVariation': pkt_time_coeff_var,
            'ResponseTimeTimeVariance': resp_time_var,
            'ResponseTimeTimeStandardDeviation': resp_time_std,
            'ResponseTimeTimeMean': resp_time_mean,
            'ResponseTimeTimeMedian': resp_time_median,
            'ResponseTimeTimeMode': resp_time_mode,
            'ResponseTimeTimeSkewFromMedian': resp_time_skew_median,
            'ResponseTimeTimeSkewFromMode': resp_time_skew_mode,
            'ResponseTimeTimeCoefficientofVariation': resp_time_coeff_var
        }
        
        # Get prediction
        pred, conf = self.analyzer.predict(features)
        
        pred_label = "MALICIOUS [!]" if pred == 1 else "BENIGN [OK]"
        
        # Display flow info
        print(f"\n[Flow #{self.flow_num}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  From: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"  Domain: {domain}")
        print(f"  Packets: {len(pkt_sizes)} | Duration: {duration:.2f}s")
        print(f"  Bytes Sent: {flow_data['bytes_sent']} | Bytes Received: {flow_data['bytes_received']}")
        print(f"  Prediction: {pred_label} (Confidence: {conf:.2%})")
        
        # Save to CSV
        with open(self.analyzer.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            # Replace special characters for CSV compatibility
            safe_label = pred_label.replace("[!]", "MALICIOUS").replace("[OK]", "BENIGN")
            writer.writerow([
                self.flow_num,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                domain,
                len(pkt_sizes),
                f"{duration:.2f}",
                flow_data['bytes_sent'],
                safe_label,
                f"{conf:.2%}"
            ])
    
    def packet_callback(self, packet):
        """Process each captured packet."""
        try:
            if packet.haslayer(DNS):
                self.packet_num += 1
                
                flow_key = self.get_flow_key(packet)
                if not flow_key:
                    return
                
                src_ip, dst_ip, src_port, dst_port = flow_key
                current_time = datetime.now().timestamp()
                
                # Initialize flow if new
                if not self.flows[flow_key]['start_time']:
                    self.flows[flow_key]['start_time'] = current_time
                
                flow = self.flows[flow_key]
                packet_size = len(packet)
                
                # Track packet data
                flow['packets'].append(self.packet_num)
                flow['packet_sizes'].append(packet_size)
                flow['bytes_sent'] += packet_size
                
                # Track inter-packet times
                if len(flow['packet_times']) > 0:
                    inter_arrival = current_time - (flow['start_time'] + sum(flow['packet_times']))
                    flow['packet_times'].append(inter_arrival)
                
                # Extract domain
                dns_layer = packet[DNS]
                if dns_layer.qdcount > 0:
                    question = dns_layer.qd[0] if isinstance(dns_layer.qd, list) else dns_layer.qd
                    domain = question.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if domain not in flow['domains']:
                        flow['domains'].append(domain)
                
                # Analyze flow after certain conditions
                # Condition: if this is first packet or periodic analysis
                if len(flow['packets']) >= 10 or (self.packet_num % 50 == 0):
                    self.analyze_flow(flow_key, flow)
                    # Reset flow for next batch
                    self.flows[flow_key] = {
                        'packets': [],
                        'packet_sizes': [],
                        'packet_times': [],
                        'response_times': [],
                        'bytes_sent': 0,
                        'bytes_received': 0,
                        'start_time': current_time,
                        'domains': flow['domains']
                    }
        
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    
    def start(self):
        """Start sniffing."""
        print("\n" + "="*70)
        print("DNS Sniffer with Flow-based Malicious Detection")
        print("="*70)
        print(f"Packets to capture: {self.packet_count if self.packet_count > 0 else 'unlimited'}")
        print(f"Interface: {self.interface or 'default'}")
        print("Analyzing flows (10+ packets per flow)...\n")
        
        try:
            sniff(
                prn=self.packet_callback,
                filter="udp port 53",
                iface=self.interface,
                store=False,
                count=self.packet_count if self.packet_count > 0 else 0
            )
        except PermissionError:
            print("ERROR: Need admin/root privileges!", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            # Analyze remaining flows
            print("\n\nAnalyzing remaining flows...\n")
            for flow_key, flow_data in self.flows.items():
                if len(flow_data['packets']) > 0:
                    self.analyze_flow(flow_key, flow_data)
            
            print(f"\n\nCaptured {self.packet_num} packets into {self.flow_num} flows")
            print(f"Results saved to: {self.analyzer.csv_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="DNS Sniffer with Malicious Detection"
    )
    parser.add_argument("-c", "--count", type=int, default=0, 
                       help="Number of packets to capture (default: unlimited)")
    parser.add_argument("-i", "--interface", help="Network interface")
    
    args = parser.parse_args()
    
    sniffer = DNSSniffer(packet_count=args.count, interface=args.interface)
    sniffer.start()


if __name__ == "__main__":
    main()
    # )
    # parser.add_argument(
    #     "-i", "--interface",
    #     help="Network interface to sniff on (e.g., eth0, wlan0)"
    # )
    # parser.add_argument(
    #     "-d", "--domain",
    #     dest="filter_domain",
    #     help="Filter DNS packets by domain"
    # )

    # Example usage:
"""
  # Capture all DNS packets (requires admin/root):
  python dns_packet_sniff.py
  
  # Capture 100 packets on specific interface:
  python dns_packet_sniff.py -c 100 -i eth0
  
  # Filter for specific domain:
  python dns_packet_sniff.py -d example.com
        """







# # Handle DNS Answers (DNSRR)
# if dns_layer.ancount > 0:
#     print("[DNS ANSWER]")
#     for i in range(dns_layer.ancount):
#         answer = dns_layer.an[i] if isinstance(dns_layer.an, list) else dns_layer.an
#         rrname = answer.rrname.decode('utf-8', errors='ignore').rstrip('.')
#         rrtype = self.get_qtype_name(answer.type)
#         ttl = answer.ttl
        
#         # Parse RDATA based on type
#         rdata = self.parse_rdata(answer)

#         print(f"  Name: {rrname}")
#         print(f"  Type: {rrtype} ({answer.type})")
#         print(f"  TTL: {ttl}")
#         print(f"  Data: {rdata}")

# # Handle DNS Authority Records (DNSRR Auth)
# if dns_layer.nscount > 0:
#     print("[DNS AUTHORITY]")
#     for i in range(dns_layer.nscount):
#         auth = dns_layer.ns[i] if isinstance(dns_layer.ns, list) else dns_layer.ns
#         auth_name = auth.rrname.decode('utf-8', errors='ignore').rstrip('.')
#         rdata = self.parse_rdata(auth)
#         print(f"  Name: {auth_name} -> {rdata}")