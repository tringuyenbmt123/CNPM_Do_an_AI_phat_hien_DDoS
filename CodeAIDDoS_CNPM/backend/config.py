import os
from backend.utils import get_default_interface

class Config:
    def __init__(self):
        self.interface = os.environ.get('INTERFACE', get_default_interface())
        self.window_size = float(os.environ.get('WINDOW_SIZE', '1.0'))
        self.data_retention_minutes = int(os.environ.get('DATA_RETENTION_MINUTES', '10'))
        self.dashboard_update_interval = int(os.environ.get('DASHBOARD_UPDATE_INTERVAL', '1'))
        self.model_path = os.environ.get('MODEL_PATH', "backend/models/random_forest_DrDoS_UDP.pkl")
        self.queue_size = int(os.environ.get('QUEUE_SIZE', '1000'))
        self.host = os.environ.get('HOST', '0.0.0.0')
        self.port = int(os.environ.get('PORT', '5000'))
        self.debug = os.environ.get('DEBUG', 'False').lower() == 'true'
        self.timestamp_display_duration = int(os.environ.get('TIMESTAMP_DISPLAY_DURATION', '60'))
        # self.pfsense_host = "192.168.1.1"
        # self.pfsense_username = "admin"
        # self.pfsense_password = "123456"
        # self.pfsense_interface = "wan"
