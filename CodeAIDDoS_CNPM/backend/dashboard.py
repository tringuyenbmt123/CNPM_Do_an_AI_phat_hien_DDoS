import os
import time
import numpy as np
from datetime import datetime
from flask import jsonify, request, send_from_directory, Response, redirect
import logging
import json
import hashlib
from backend.detector import DDoSDetector
from backend.config import Config
import pandas as pd
import paramiko

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DDoSDetector')

def block_ip_pfsense(host, username, password, interface, ip_to_block):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host, username=username, password=password)
        command = f"easyrule block {interface} {ip_to_block}"
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh_client.close()
        if error:
            logger.error(f"pfSense error: {error}")
            return False, f"Failed to block IP {ip_to_block}: {error}"
        logger.info(f"Blocked IP {ip_to_block} on interface {interface}")
        return True, f"Blocked IP {ip_to_block} on interface {interface}"
    except Exception as e:
        logger.error(f"Failed to block IP {ip_to_block}: {str(e)}", exc_info=True)
        return False, f"Failed to block IP {ip_to_block}: {str(e)}"

def setup_dashboard(flask_app, detector=None, config=None):
    if detector is None:
        detector = DDoSDetector()
    if config is None:
        config = Config()

    STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../public'))
    logger.info(f"Static directory for dashboard: {STATIC_DIR}")

    heatmap_cache = {'hash': None, 'data': None, 'timestamp': 0}
    feature_cache = {'hash': None, 'data': None, 'timestamp': 0}
    recent_data_cache = {'hash': None, 'data': None, 'timestamp': 0}

    ip_cache = {'src_ips': [], 'dst_ips': [], 'timestamp': 0}
    CACHE_TIMEOUT = 15
    IP_CACHE_TIMEOUT = 1800  

    @flask_app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response

    def format_timestamp(ts):
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    def get_recent_data_cached(minutes=30):  
        try:
            with detector.data_lock:
                if detector.temp_data:
                    detector._update_traffic_data()

                current_time = time.time()
                data_hash = hashlib.md5(detector.traffic_data.to_json().encode()).hexdigest()

                if (recent_data_cache['hash'] == data_hash and 
                    current_time - recent_data_cache['timestamp'] < CACHE_TIMEOUT):
                    logger.info("Returning cached recent data")
                    return recent_data_cache['data'].copy()

                cutoff = current_time - (minutes * 60)
                recent = detector.traffic_data[detector.traffic_data['timestamp'] > cutoff]

                if 'is_attack' not in recent.columns or recent.empty:
                    recent = pd.DataFrame(columns=detector.traffic_data.columns)

                recent_data_cache['hash'] = data_hash
                recent_data_cache['data'] = recent
                recent_data_cache['timestamp'] = current_time

                logger.info(f"get_recent_data: {len(recent)} rows, columns: {recent.columns.tolist()}")
                return recent.copy()
        except Exception as e:
            logger.error(f"Error in get_recent_data_cached: {e}", exc_info=True)
            return pd.DataFrame()

    def create_heatmap_data(recent_data):
        logger.info(f"create_heatmap_data: Received recent_data with {len(recent_data)} rows")
        if not recent_data.empty:
            logger.info(f"Columns in recent_data: {recent_data.columns.tolist()}")

        current_time = time.time()

        if recent_data.empty or len(recent_data) <= 1:
            logger.info("Insufficient data for heatmap, returning sample dataset")
            return {
                'src_ips': ['192.168.1.1', '192.168.1.2'],
                'dst_ips': ['192.168.1.3', '192.168.1.4'],
                'z_values': [[10, 20], [30, 40]],
                'blocked_ips': list(detector.blocked_ips)
            }

        required_columns = ['source ip', 'destination ip', 'flow packets/s']
        if not all(col in recent_data.columns for col in required_columns):
            logger.error(f"Missing required columns in recent_data: {required_columns}")
            return {
                'src_ips': ['192.168.1.1', '192.168.1.2'],
                'dst_ips': ['192.168.1.3', '192.168.1.4'],
                'z_values': [[10, 20], [30, 40]],
                'blocked_ips': list(detector.blocked_ips)
            }

        if current_time - ip_cache['timestamp'] > IP_CACHE_TIMEOUT or not ip_cache['src_ips']:
            long_term_data = detector.traffic_data[
                detector.traffic_data['timestamp'] > (current_time - 60 * 60)
            ]
            ip_cache['src_ips'] = long_term_data['source ip'].value_counts().head(15).index.tolist()
            ip_cache['dst_ips'] = long_term_data['destination ip'].value_counts().head(15).index.tolist()
            ip_cache['timestamp'] = current_time
            logger.info(f"Updated IP cache: {len(ip_cache['src_ips'])} src_ips, {len(ip_cache['dst_ips'])} dst_ips")

        src_ips = ip_cache['src_ips']
        dst_ips = ip_cache['dst_ips']

        z_values = np.zeros((len(src_ips), len(dst_ips)))
        for i, src in enumerate(src_ips):
            for j, dst in enumerate(dst_ips):
                subset = recent_data[
                    (recent_data['source ip'] == src) & (recent_data['destination ip'] == dst)
                ]
                if not subset.empty:
                    z_values[i][j] = subset['flow packets/s'].sum()
                else:
                    z_values[i][j] = 0

        if np.max(z_values) == 0:
            logger.warning("All z_values are 0, adding sample data for visualization")
            z_values[0][0] = 10
            z_values[0][1] = 20
            z_values[1][0] = 30
            z_values[1][1] = 40

        heatmap_data = {
            'src_ips': src_ips,
            'dst_ips': dst_ips,
            'z_values': z_values.tolist(),
            'blocked_ips': list(detector.blocked_ips)
        }
        logger.info(f"Heatmap data created: {len(src_ips)} src_ips, {len(dst_ips)} dst_ips")
        return heatmap_data

    @flask_app.route('/')
    def home():
        try:
            if not os.path.exists(os.path.join(STATIC_DIR, 'index.html')):
                logger.error(f"index.html not found in {STATIC_DIR}")
                return jsonify({'error': 'Homepage index.html not found'}), 404
            logger.info("Serving homepage index.html")
            response = send_from_directory(STATIC_DIR, 'index.html')
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            return response
        except Exception as e:
            logger.error(f"Error serving homepage: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/favicon.ico')
    def serve_favicon():
        try:
            favicon_path = os.path.join(STATIC_DIR, 'favicon.ico')
            if not os.path.exists(favicon_path):
                logger.error(f"favicon.ico not found in {STATIC_DIR}")
                return jsonify({'error': 'Favicon not found'}), 404
            logger.info("Serving favicon.ico")
            response = send_from_directory(STATIC_DIR, 'favicon.ico')
            response.headers['Cache-Control'] = 'public, max-age=86400'
            return response
        except Exception as e:
            logger.error(f"Error serving favicon: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/dashboard/')
    def dashboard():
        try:
            if not os.path.exists(os.path.join(STATIC_DIR, 'index.html')):
                logger.error(f"index.html not found in {STATIC_DIR}")
                return jsonify({'error': 'Dashboard index.html not found'}), 404
            logger.info("Serving dashboard index.html")
            response = send_from_directory(STATIC_DIR, 'index.html')
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            return response
        except Exception as e:
            logger.error(f"Error serving dashboard: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/dashboard/<path:path>')
    def serve_dashboard_static(path):
        try:
            full_path = os.path.join(STATIC_DIR, path)
            logger.info(f"Attempting to serve static file: {full_path}")
            if not os.path.exists(full_path):
                logger.error(f"Static file {path} not found in {STATIC_DIR}")
                return jsonify({'error': f'Static file {path} not found'}), 404
            logger.info(f"Serving static file: {path}")
            response = send_from_directory(STATIC_DIR, path)
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            return response
        except Exception as e:
            logger.error(f"Error serving static file {path}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/config')
    def get_config():
        try:
            config_data = {
                'interface': config.interface,
                'window_size': config.window_size,
                'data_retention_minutes': config.data_retention_minutes,
                'dashboard_update_interval': config.dashboard_update_interval,
                'timestamp_display_duration': config.timestamp_display_duration
            }
            logger.info(f"Returning config: {config_data}")
            return jsonify(config_data)
        except Exception as e:
            logger.error(f"Error in get_config: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/combined_data')
    def get_combined_data():
        logger.info(f"Received request for /api/combined_data from {request.remote_addr}")
        try:
            recent_data = get_recent_data_cached(minutes=30)
            alerts = detector.get_alerts(count=100)
            attack_stats = detector.get_attack_stats()
            top_ips = detector.get_top_ips()
            ip_attack_counts = detector.get_ip_attack_counts()

            total_traffic = recent_data['flow bytes/s'].sum() / 1_000_000
            total_traffic = f"{total_traffic:.1f}M"

            valid_data = recent_data[
                recent_data['timestamp'] >= time.time() - config.timestamp_display_duration
            ]
            timestamps = [format_timestamp(ts) for ts in valid_data['timestamp']]

            alert_counts = [0] * len(timestamps)
            for alert in alerts:
                alert_time = alert['time']
                if alert_time in timestamps:
                    idx = timestamps.index(alert_time)
                    alert_counts[idx] += 1

            attack_points = []
            if 'is_attack' in valid_data.columns:
                attack_indices = valid_data[valid_data['is_attack'].astype(bool)].index
                attack_points = [
                    {'time': format_timestamp(valid_data.loc[i, 'timestamp']), 'value': valid_data.loc[i, 'flow bytes/s']}
                    for i in attack_indices if format_timestamp(valid_data.loc[i, 'timestamp']) in timestamps
                ]

            network_traffic = {
                'labels': timestamps,
                'bytes': valid_data['flow bytes/s'].tolist(),
                'alerts': alert_counts,
                'attackPoints': attack_points
            }

            recent_alerts = []
            for alert in reversed(alerts[-20:]):
                ip = alert.get('source_ip', detector.extract_ip_from_message(alert['message']))
                attack_count = ip_attack_counts.get(ip, 0) if ip else 0
                severity = 'Critical' if 'Blocked' in alert['mitigation'] else 'High'
                recent_alerts.append({
                    'time': alert['time'],
                    'severity': severity,
                    'sourceIp': ip if ip else 'Unknown',
                    'description': alert['message'],
                    'connections': attack_count,
                    'isAttack': 'Blocked' in alert['mitigation']
                })
            logger.info(f"Prepared {len(recent_alerts)} recent alerts: {recent_alerts}")

            attackers_by_country = []
            country_counts = {}
            for ip_data in top_ips:
                country = detector.get_country_from_ip(ip_data['ip']) if hasattr(detector, 'get_country_from_ip') else 'Unknown'
                country_counts[country] = country_counts.get(country, 0) + ip_data['count']
            for country, count in country_counts.items():
                attackers_by_country.append({'country': country, 'count': count})

            ip_list = [
                {
                    'sourceIp': ip_data['ip'],
                    'connections': ip_data['count'],
                    'isAttack': ip_data['ip'] in detector.blocked_ips or ip_data['ip'] in ip_attack_counts
                }
                for ip_data in top_ips
            ]
            for ip in detector.blocked_ips:
                if not any(item['sourceIp'] == ip for item in ip_list):
                    ip_list.append({
                        'sourceIp': ip,
                        'connections': ip_attack_counts.get(ip, 0),
                        'isAttack': True
                    })

            alerts = detector.get_alerts()
            current_time = time.time() 
            if alerts:
                last_alert_time = time.strptime(alerts[-1]['time'], '%Y-%m-%d %H:%M:%S')
                last_alert_timestamp = time.mktime(time.localtime(current_time)) - time.mktime(last_alert_time)
            
            if detector.current_status == 'Normal' or (not alerts and last_alert_timestamp > 15):
                status = 'Normal'
            else:
                status = 'Under Attack'

            metrics_window = 15  # giây
            current_time = time.time()
            metrics_data = recent_data[recent_data['timestamp'] >= current_time - metrics_window]

            metrics = {
                'flow_bytes_s': metrics_data['flow bytes/s'].mean() if not metrics_data.empty else 0,
                'flow_packets_s': metrics_data['flow packets/s'].mean() if not metrics_data.empty else 0,
                'unique_sources': len(metrics_data['source ip'].unique()) if not metrics_data.empty else 0,
                'is_attack': bool(metrics_data['is_attack'].any()) if 'is_attack' in metrics_data.columns else False
            }

            ddos_alerts = len(alerts)
            detected_attacks = attack_stats['total_attacks']
            active_attacks = len([
                alert for alert in alerts
                if (time.time() - time.mktime(datetime.strptime(alert['time'], '%Y-%m-%d %H:%M:%S').timetuple())) < 60
            ])

            response_data = {
                'dashboard': {
                    'totalTraffic': total_traffic,
                    'ddosAlerts': ddos_alerts,
                    'detectedAttacks': detected_attacks,
                    'activeAttacks': active_attacks,
                    'networkTraffic': network_traffic,
                    'attackersByCountry': attackers_by_country,
                    'recentAlerts': recent_alerts,
                    'ipList': ip_list
                },
                'status': status,
                'metrics': metrics
            }
            logger.info(f"Returning combined data: {len(ip_list)} IPs, {len(recent_alerts)} alerts, "
                       f"ddosAlerts={ddos_alerts}, detectedAttacks={detected_attacks}, activeAttacks={active_attacks}")
            return jsonify(response_data)
        except Exception as e:
            logger.error(f"Error in get_combined_data: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/stream')
    def stream():
        def generate():
            while True:
                try:
                    recent_data = get_recent_data_cached()
                    data_hash = hashlib.md5(recent_data.to_json().encode()).hexdigest()
                    current_time = time.time()

                    if (heatmap_cache['hash'] != data_hash or 
                        current_time - heatmap_cache['timestamp'] >= CACHE_TIMEOUT):
                        try:
                            heatmap_data = create_heatmap_data(recent_data)
                            heatmap_cache['hash'] = data_hash
                            heatmap_cache['data'] = heatmap_data
                            heatmap_cache['timestamp'] = current_time
                            logger.info("SSE: Updated heatmap data")
                        except Exception as e:
                            logger.error(f"Error creating heatmap data: {e}", exc_info=True)
                            heatmap_cache['data'] = {'error': str(e)}

                    if (feature_cache['hash'] != data_hash or 
                        current_time - feature_cache['timestamp'] >= CACHE_TIMEOUT):
                        try:
                            result = detector.get_feature_importance()
                            if result is not None:
                                features, importance_dict = result
                                sorted_items = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
                                feature_data = {
                                    'features': [item[0] for item in sorted_items],
                                    'importance': [item[1] for item in sorted_items]
                                }
                                feature_cache['hash'] = data_hash
                                feature_cache['data'] = feature_data
                                feature_cache['timestamp'] = current_time
                                logger.info("SSE: Updated feature importance")
                            else:
                                feature_cache['data'] = {'features': [], 'importance': []}
                        except Exception as e:
                            logger.error(f"Error getting feature importance: {e}", exc_info=True)
                            feature_cache['data'] = {'error': str(e)}

                    stream_data = {'heatmap': heatmap_cache['data'], 'features': feature_cache['data']}
                    logger.info(f"Sending SSE data: {stream_data}")
                    yield f"data: {json.dumps(stream_data)}\n\n"
                except Exception as e:
                    logger.error(f"Error in SSE stream: {e}", exc_info=True)
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(config.dashboard_update_interval)

        response = Response(generate(), mimetype='text/event-stream')
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['Connection'] = 'keep-alive'
        return response

    @flask_app.route('/api/dashboard_data')
    def deprecated_dashboard_data():
        logger.warning(f"Deprecated endpoint /api/dashboard_data called from {request.remote_addr}")
        return redirect('/api/combined_data', code=301)

    @flask_app.route('/api/block_ip', methods=['POST'])
    def block_ip():
        try:
            data = request.get_json()
            ip_to_block = data.get('ip')
            if not ip_to_block:
                logger.error("No IP provided in block_ip request")
                return jsonify({'success': False, 'message': 'IP address is required'}), 400

            success, message = block_ip_pfsense(
                host=config.pfsense_host,
                username=config.pfsense_username,
                password=config.pfsense_password,
                interface=config.pfsense_interface,
                ip_to_block=ip_to_block
            )

            if success:
                with detector.data_lock:
                    detector.blocked_ips.add(ip_to_block)
                    detector.attack_stats['blocked_ips'] = len(detector.blocked_ips)
                logger.info(f"Blocked IP {ip_to_block} and updated detector")
                return jsonify({'success': True, 'message': message}), 200
            return jsonify({'success': False, 'message': message}), 500
        except Exception as e:
            logger.error(f"Error in block_ip: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'message': f"Error blocking IP: {str(e)}"}), 500

    return flask_app