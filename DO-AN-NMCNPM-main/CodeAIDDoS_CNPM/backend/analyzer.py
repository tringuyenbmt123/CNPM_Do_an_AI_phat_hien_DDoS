import time
from threading import Thread
from collections import defaultdict
import logging
import socket
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from backend.utils import detector_queue 
from queue import Full

logger = logging.getLogger('DDoSDetector')

class TrafficAnalyzer:
    def __init__(self, interface, window_size=1, detector=None):
        self.interface = interface
        self.window_size = window_size
        self.flows = defaultdict(list)
        self.start_time = time.time()
        self.model = self.load_model()
        self.detector = detector
        self.running = True
        self.local_ip = socket.gethostbyname(socket.gethostname())

    def load_model(self):
        try:
            model_path = "backend/models/random_forest_DrDoS_UDP.pkl"
            if not os.path.exists(model_path):
                logger.warning(f"Not found model: {model_path}")
                return None
            if os.path.getsize(model_path) == 0:
                logger.warning(f"Model {model_path} is empty.")
                return None
            
            with open(model_path, 'rb') as f:
                first_byte = f.read(1)
                if not first_byte:
                    logger.error(f"Model {model_path} is empty or corrupted.")
                    return None
            
            logger.info(f"Loading model from {model_path}")
            model = joblib.load(model_path)
            logger.info(f"Model loaded successfully from {model_path}")
            return model
        except Exception as e:
            logger.error(f"Error when load model: {e}", exc_info=True)
            return None

    def packet_callback(self, packet):
        try:
            if not self.running or IP not in packet:
                return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            
            logger.debug(f"Captured packet: {src_ip} -> {dst_ip}, Protocol: {protocol}")

            pkt_data = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_length': len(packet),
                'ip_header_len': packet[IP].ihl * 4,
                'tcp_header_len': packet[TCP].dataofs * 4 if TCP in packet else 0,
                'init_win': packet[TCP].window if TCP in packet else 0,
                'is_http': (dst_port == 80 or src_port == 80 or dst_port == 443 or src_port == 443)
            }
            
            self.flows[flow_id].append(pkt_data)

            if len(self.flows[flow_id]) >= 60 or (time.time() - self.start_time >= 1.0):
                self._process_flows_for_single_flow(flow_id)
                self.start_time = time.time()

        except Exception as e:
            logger.error(f"Error in packet_callback: {e}", exc_info=True)

    def _process_flows_for_single_flow(self, flow_id):
        if flow_id in self.flows:
            features_by_flow = self.extract_features_by_flow(flow_id)
            self.process_and_predict(features_by_flow)
            del self.flows[flow_id]

    def extract_features_by_flow(self, flow_id=None):
        features_by_flow = {}
        
        if flow_id:
            if flow_id in self.flows:
                target_flows = [(flow_id, self.flows[flow_id])]
            else:
                return features_by_flow
        else:
            target_flows = self.flows.items()
        
        for fid, packets in target_flows:
            total_packets = len(packets)
            if total_packets == 0:
                continue

            timestamps = sorted(pkt['timestamp'] for pkt in packets)
            time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else self.window_size
            time_span = max(time_span, 0.001)
            
            flow_packets_s = total_packets / time_span
            total_bytes = sum(pkt['packet_length'] for pkt in packets)
            flow_bytes_s = total_bytes / time_span

            src_ip = packets[0]['src_ip']
            dst_ip = packets[0]['dst_ip']
            
            fwd_packets = [p for p in packets if p['src_ip'] == src_ip]
            bwd_packets = [p for p in packets if p['dst_ip'] == src_ip]
            
            fwd_header_length = sum(p['ip_header_len'] + p['tcp_header_len'] for p in fwd_packets) if fwd_packets else 0
            bwd_header_length = sum(p['ip_header_len'] + p['tcp_header_len'] for p in bwd_packets) if bwd_packets else 0
            min_seg_size_forward = min((p['packet_length'] for p in fwd_packets), default=0)

            init_win_bytes_forward = next((p['init_win'] for p in fwd_packets if p['init_win'] > 0), 0)
            init_win_bytes_backward = next((p['init_win'] for p in bwd_packets if p['init_win'] > 0), 0)
            simillarhttp = "HTTP" if any(p['is_http'] for p in packets) else "Non-HTTP"

            features_by_flow[fid] = {
                'flow id': fid,
                'source ip': src_ip,
                'destination ip': dst_ip,
                'flow bytes/s': flow_bytes_s,
                'flow packets/s': flow_packets_s,
                'fwd header length': fwd_header_length,
                'bwd header length': bwd_header_length,
                'fwd header length.1': fwd_header_length,
                'init_win_bytes_forward': init_win_bytes_forward,
                'init_win_bytes_backward': init_win_bytes_backward,
                'min_seg_size_forward': min_seg_size_forward,
                'simillarhttp': simillarhttp
            }
        return features_by_flow

    def process_and_predict(self, features_by_flow):
        if not self.model or not self.detector or not features_by_flow:
            logger.warning("Cannot predict: model, detector, or features missing")
            return

        for flow_id, features in features_by_flow.items():
            try:
                feature_vector = [
                    float(features.get('flow bytes/s', 0)),
                    float(features.get('flow packets/s', 0)),
                    float(features.get('fwd header length', 0)),
                    float(features.get('bwd header length', 0)),
                    float(features.get('fwd header length.1', 0)),
                    float(features.get('init_win_bytes_forward', 0)),
                    float(features.get('init_win_bytes_backward', 0)),
                    float(features.get('min_seg_size_forward', 0))
                ]
                feature_names = [
                    'flow bytes/s', 'flow packets/s', 'fwd header length', 'bwd header length',
                    'fwd header length.1', 'init_win_bytes_forward', 'init_win_bytes_backward',
                    'min_seg_size_forward'
                ]
                feature_vector_df = pd.DataFrame([feature_vector], columns=feature_names)
                attack_prob = self.model.predict_proba(feature_vector_df)[0][1]
                is_attack = attack_prob > 0.7 and features['flow packets/s'] > 100 and features['flow bytes/s'] > 5000
                priority = 1 if is_attack else 0
                
                logger.info(f"Processed flow {flow_id}: Src={features['source ip']}, Dst={features['destination ip']}, "
                           f"Bytes/s={features['flow bytes/s']:.2f}, Packets/s={features['flow packets/s']:.2f}, "
                           f"Attack prob={attack_prob:.2f}, Is attack={is_attack}")
                
                try:
                    detector_queue.put((features, is_attack, priority), block=False)
                except Full:
                    logger.warning(f"Queue full, dropping flow {flow_id}")
                    detector_queue.get()
                    detector_queue.put((features, is_attack, priority), block=False)
            except Exception as e:
                logger.error(f"Error predicting for flow {flow_id}: {e}", exc_info=True)

    def start_capture(self):
        try:
            bpf_filter = f"not host {self.local_ip}"
            logger.info(f"Starting packet capture on {self.interface} with filter: {bpf_filter}")
            sniff(iface=self.interface, prn=self.packet_callback, filter=bpf_filter, store=0, 
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"Error in start_capture: {e}", exc_info=True)

    def shutdown(self):
        self.running = False

def run_traffic_analyzer(analyzer):
    try:
        logger.info(f"Starting TrafficAnalyzer on interface: {analyzer.interface}")
        analyzer.start_capture()
    except Exception as e:
        logger.error(f"Error in run_traffic_analyzer: {e}", exc_info=True)