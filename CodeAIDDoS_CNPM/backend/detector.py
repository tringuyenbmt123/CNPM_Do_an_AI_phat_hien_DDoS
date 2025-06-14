import pandas as pd
import time
from threading import Lock
import logging
import socket
import threading
import re
import datetime
import subprocess, os

logger = logging.getLogger('DDoSDetector')

class DDoSDetector:
    def __init__(self):
        self.traffic_data = pd.DataFrame({
            'timestamp': [], 'flow id': [], 'source ip': [], 'destination ip': [],
            'flow bytes/s': [], 'flow packets/s': [], 'fwd header length': [],
            'bwd header length': [], 'fwd header length.1': [],
            'init_win_bytes_forward': [], 'init_win_bytes_backward': [],
            'min_seg_size_forward': [], 'simillarhttp': [], 'is_attack': []
        })
        self.alerts = []
        self.current_status = "Normal"
        self.blocked_ips = set()
        self.attack_stats = {'total_attacks': 0, 'blocked_ips': 0, 'last_attack': None}
        self.data_lock = Lock()
        self.temp_data = []
        self.running = True
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.last_attack_time = None
        self.attack_grace_period = 10

    def add_sample(self, flow_data, is_attack):
        try:
            required_fields = ['source ip', 'destination ip', 'flow bytes/s', 'flow packets/s']
            for field in required_fields:
                if field not in flow_data:
                    logger.error(f"Missing field {field} in flow_data: {flow_data}")
                    return

            flow_data['timestamp'] = time.time()
            flow_data['is_attack'] = bool(is_attack)  # Đảm bảo is_attack là boolean
            logger.debug(f"Adding sample: {flow_data}, is_attack={is_attack}")

            with self.data_lock:
                self.temp_data.append(flow_data)
                if len(self.temp_data) >= 100 or is_attack:
                    self._update_traffic_data()

            if is_attack:
                self._handle_attack(flow_data)
                logger.info(f"Attack sample processed: {flow_data}")
            else:
                self._check_normal_status()
                logger.debug("No attack detected in this sample")
        except Exception as e:
            logger.error(f"Error in add_sample: {e}", exc_info=True)

    def _update_traffic_data(self):
        try:
            if not self.temp_data:
                return

            new_data = pd.DataFrame(self.temp_data)
            for col in self.traffic_data.columns:
                if col not in new_data.columns:
                    new_data[col] = None

            self.traffic_data = pd.concat([self.traffic_data, new_data], ignore_index=True)
            self.temp_data = []

            cutoff = time.time() - (10 * 60)  # 10 minutes sẽ xóa dữ liệu cũ
            self.traffic_data = self.traffic_data[self.traffic_data['timestamp'] > cutoff]
            logger.info(f"Updated traffic_data, Rows now: {len(self.traffic_data)}")
        except Exception as e:
            logger.error(f"Error in _update_traffic_data: {e}", exc_info=True)

    def _handle_attack(self, flow_data):
        with self.data_lock:
            source_ip = flow_data['source ip']
            if source_ip == self.local_ip:
                logger.info(f"Ignoring attack from local IP: {source_ip}")
                return

            timestamp = format_timestamp(time.time())
            alert_message = (f"DDoS Attack Detected! Source IP: {source_ip}, "
                           f"Flow bytes/s: {flow_data['flow bytes/s']:.2f}, "
                           f"Packets/s: {flow_data['flow packets/s']:.2f}")
            mitigation = f"Suggested: Block traffic from {source_ip}"

            self.alerts.append({
                'time': timestamp,
                'source_ip': source_ip,  # Lưu trữ source_ip riêng để dễ truy xuất
                'message': alert_message,
                'mitigation': mitigation
            })

            if len(self.alerts) > 100:
                self.alerts = self.alerts[-100:]

            self.current_status = "Under Attack"
            self.last_attack_time = time.time()
            self.attack_stats['total_attacks'] += 1
            self.attack_stats['last_attack'] = timestamp

            if (source_ip not in self.blocked_ips and
                flow_data['flow packets/s'] > 1000 and
                flow_data['flow bytes/s'] > 50000):
                self.blocked_ips.add(source_ip)
                self.attack_stats['blocked_ips'] = len(self.blocked_ips)
                self._block_ip(source_ip)
                self.alerts[-1]['mitigation'] = f'Blocked traffic from {source_ip}'
                logger.warning(f"Blocked IP: {source_ip} due to attack")

            logger.warning(f"Attack details - Src: {source_ip}, "
                         f"Bytes/s: {flow_data['flow bytes/s']:.2f}, "
                         f"Packets/s: {flow_data['flow packets/s']:.2f}, "
                         f"Blocked: {source_ip in self.blocked_ips}, "
                         f"Total Attacks: {self.attack_stats['total_attacks']}")
        logger.info(f"Current alerts: {len(self.alerts)} alerts stored")

    def _block_ip(self, ip):
        script_path = os.path.join(os.path.dirname(__file__), 'block.py')
        result = subprocess.run(['sudo', 'python3', script_path, ip], capture_output=True, text=True)

        print(f"Command: {' '.join(['sudo', 'python3', script_path, ip])}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")

    def _unblock_ip(self, ip):
        script_path = os.path.join(os.path.dirname(__file__), 'unblock.py')
        result = subprocess.run(['sudo', 'python3', script_path, ip], capture_output=True, text=True)

        print(f"Command: {' '.join(['sudo', 'python3', script_path, ip])}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")

        self.blocked_ips.discard(ip)

    def _check_normal_status(self):
        with self.data_lock:
            if self.last_attack_time is not None:
                time_since_last_attack = time.time() - self.last_attack_time
                if time_since_last_attack > self.attack_grace_period:
                    self.current_status = "Normal"
                    logger.info("Status changed to Normal")
            elif len(self.alerts) == 0:
                self.current_status = "Normal"
                logger.debug("No alerts, status remains Normal")

    def get_recent_data(self, minutes=5):
        try:
            with self.data_lock:
                if self.temp_data:
                    self._update_traffic_data()

                cutoff = time.time() - (minutes * 60)
                recent = self.traffic_data[self.traffic_data['timestamp'] > cutoff]

                logger.info(f"get_recent_data: {len(recent)} rows, columns: {recent.columns.tolist()}")

                if 'is_attack' not in recent.columns or recent.empty:
                    return pd.DataFrame(columns=self.traffic_data.columns)

                return recent.copy()
        except Exception as e:
            logger.error(f"Error in get_recent_data: {e}", exc_info=True)
            return pd.DataFrame()

    def get_alerts(self, count=20):
        with self.data_lock:
            alerts = self.alerts[-count:] if count else self.alerts.copy()
            logger.info(f"Returning {len(alerts)} alerts from get_alerts")
            return alerts

    def get_ip_attack_counts(self):
        with self.data_lock:
            ip_counts = {}
            for alert in self.alerts:
                ip = self.extract_ip_from_message(alert['message'])
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            logger.info(f"IP attack counts: {ip_counts}")
            return ip_counts

    def extract_ip_from_message(self, message):
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        match = re.search(ip_pattern, message)
        ip = match.group(0) if match else None
        if not ip:
            logger.debug(f"No IP found in message: {message}")
        return ip

    def get_attack_stats(self):
        with self.data_lock:
            stats = self.attack_stats.copy()
            stats['blocked_ips_list'] = list(self.blocked_ips)
            logger.info(f"Attack stats: {stats}")
            return stats

    def get_top_ips(self, count=5):
        try:
            recent_data = self.get_recent_data()
            if recent_data.empty:
                logger.info("No recent data for top IPs")
                return []

            ip_counts = recent_data['source ip'].value_counts().head(count)
            top_ips = [{'ip': ip, 'count': count} for ip, count in ip_counts.items()]
            logger.info(f"Top IPs: {top_ips}")
            return top_ips
        except Exception as e:
            logger.error(f"Error in get_top_ips: {e}", exc_info=True)
            return []

    def get_feature_importance(self):
        try:
            model = None
            for thread in threading.enumerate():
                if hasattr(thread, '_target') and thread._target is not None and thread._target.__name__ == 'run_traffic_analyzer':
                    if hasattr(thread, '_args') and len(thread._args) > 0:
                        analyzer = thread._args[0]
                        if hasattr(analyzer, 'model'):
                            model = analyzer.model
                            break

            if model and hasattr(model, 'feature_importances_'):
                features = [
                    'flow bytes/s', 'flow packets/s', 'fwd header length',
                    'bwd header length', 'fwd header length.1', 'init_win_bytes_forward',
                    'init_win_bytes_backward', 'min_seg_size_forward'
                ]
                importances = model.feature_importances_

                min_len = min(len(features), len(importances))
                features = features[:min_len]
                importances = importances[:min_len]

                importance_dict = dict(zip(features, importances))
                logger.info(f"Feature importance: {importance_dict}")
                return features, importance_dict
            else:
                logger.warning("No model found for feature importance")
                return [], {}
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}", exc_info=True)
            return [], {}

    def shutdown(self):
        self.running = False

def format_timestamp(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
