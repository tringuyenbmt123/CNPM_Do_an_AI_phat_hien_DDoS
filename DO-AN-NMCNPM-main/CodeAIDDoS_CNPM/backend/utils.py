import logging
from queue import Queue, Empty
import argparse
import sys
import psutil
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/ddos_detector.log')  # Adjusted log file path
    ]
)
logger = logging.getLogger('DDoSDetector')

detector_queue = Queue(maxsize=1000)

def detector_updater(queue, detector):
    """Thread xử lý dữ liệu từ queue và cập nhật detector"""
    while detector.running:
        try:
            features, is_attack, priority = queue.get(timeout=0.1)
            if not isinstance(features, dict):
                logger.error(f"Invalid features format: {features}")
                continue
            detector.add_sample(features, is_attack)
            queue.task_done()
        except Empty:
            continue
        except Exception as e:
            logger.error(f"Error in detector_updater: {e}", exc_info=True)

def signal_handler(sig, frame):
    """Xử lý tín hiệu để dừng ứng dụng an toàn"""
    logger.info("Shutting down application...")
    sys.exit(0)

def get_default_interface():
    """Tự động lấy interface mạng chính (không phải loopback)"""
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return name
    return "eth0" 

def parse_args():
    """Xử lý tham số dòng lệnh"""
    parser = argparse.ArgumentParser(description='DDoS Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to capture packets', default=get_default_interface())
    parser.add_argument('-w', '--window', type=float, help='Time window size for traffic analysis (seconds)', default=1.0)
    parser.add_argument('-r', '--retention', type=int, help='Data retention time (minutes)', default=10)
    parser.add_argument('-u', '--update', type=int, help='Dashboard update interval (seconds)', default=1)
    parser.add_argument('-m', '--model', help='Path to ML model file', default="backend/models/random_forest_DrDoS_UDP.pkl")
    parser.add_argument('-p', '--port', type=int, help='Web server port', default=5000)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    return args