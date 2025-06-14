import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
from threading import Thread
import signal
import logging
from backend.config import Config
from backend.detector import DDoSDetector
from backend.analyzer import TrafficAnalyzer, run_traffic_analyzer
from backend.utils import detector_queue, detector_updater, signal_handler, parse_args, logger
from backend.dashboard import setup_dashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DDoSDetector')

# Initialize Flask app
flask_app = Flask(__name__, static_folder="../public", template_folder="../templates")
CORS(flask_app)

# Initialize configuration and detector
config = Config()
detector = DDoSDetector()

# Setup dashboard routes
flask_app = setup_dashboard(flask_app, detector, config)
logger.info("Dashboard routes initialized")

@flask_app.route('/api/status')
def deprecated_status():
    """Deprecated API for system status"""
    logger.warning(f"Deprecated endpoint /api/status called from {request.remote_addr}. Referer: {request.headers.get('Referer')}, User-Agent: {request.headers.get('User-Agent')}")
    return jsonify({'error': 'Endpoint /api/status is deprecated. Use /api/combined_data'}), 404

@flask_app.route('/api/metrics')
def deprecated_metrics():
    """Deprecated API for metrics"""
    logger.warning(f"Deprecated endpoint /api/metrics called from {request.remote_addr}. Referer: {request.headers.get('Referer')}, User-Agent: {request.headers.get('User-Agent')}")
    return jsonify({'error': 'Endpoint /api/metrics is deprecated. Use /api/combined_data'}), 404

@flask_app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """API to get and update configuration"""
    if request.method == 'GET':
        return jsonify({
            'interface': config.interface,
            'window_size': config.window_size,
            'data_retention_minutes': config.data_retention_minutes,
            'dashboard_update_interval': config.dashboard_update_interval
        })
    elif request.method == 'POST':
        try:
            data = request.get_json()
            if 'window_size' in data:
                config.window_size = float(data['window_size'])
            if 'data_retention_minutes' in data:
                config.data_retention_minutes = int(data['data_retention_minutes'])
            if 'dashboard_update_interval' in data:
                config.dashboard_update_interval = int(data['dashboard_update_interval'])
            return jsonify({'status': 'success'})
        except Exception as e:
            logger.error(f"Error updating config: {e}", exc_info=True)
            return jsonify({'status': 'error', 'message': str(e)}), 500

@flask_app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    """API to unblock an IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP address required'}), 400
        if ip in detector.blocked_ips:
            detector._unblock_ip(ip)
            return jsonify({'status': 'success', 'message': f'Unblocked IP {ip}'})
        return jsonify({'status': 'error', 'message': f'IP {ip} not blocked'}), 404
    except Exception as e:
        logger.error(f"Error in unblock_ip: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    args = parse_args()
    
    updater_thread = Thread(
        target=detector_updater,
        args=(detector_queue, detector),
        name="DetectorUpdaterThread"
    )
    updater_thread.daemon = True
    updater_thread.start()
    logger.info("Detector updater thread started")

    analyzer = TrafficAnalyzer(
        interface=config.interface,
        window_size=config.window_size,
        detector=detector
    )
    capture_thread = Thread(
        target=run_traffic_analyzer,
        args=(analyzer,),
        name="TrafficCaptureThread"
    )
    capture_thread.daemon = True
    capture_thread.start()
    logger.info("Traffic capture thread started")

    logger.info(f"Starting web server on {config.host}:{config.port}")
    flask_app.run(
        debug=config.debug,
        host=config.host,
        port=config.port,
        threaded=True
    )