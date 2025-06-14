import { memo, useState } from 'react';

const SettingsView = memo(({ data, config, setConfig }) => {
    const [formData, setFormData] = useState({
        window_size: config.window_size,
        data_retention_minutes: config.data_retention_minutes,
        dashboard_update_interval: config.dashboard_update_interval
    });

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSaveConfig = async () => {
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            const result = await response.json();
            if (result.status === 'success') {
                setConfig(formData);
                alert('Configuration updated successfully');
            } else {
                alert('Failed to update configuration: ' + result.message);
            }
        } catch (error) {
            console.error('Error updating config:', error);
            alert('Failed to update configuration');
        }
    };

    return (
        <div className="flex-1 p-6 bg-gray-800 text-white">
            <h1 className="text-3xl font-bold mb-6">Settings</h1>
            <div className="bg-gray-700 p-4 rounded-lg">
                <div className="mb-4">
                    <label className="block mb-2">Network Interface</label>
                    <input 
                        type="text" 
                        value={config.interface} 
                        className="bg-gray-600 p-2 rounded w-full" 
                        readOnly 
                    />
                </div>
                <div className="mb-4">
                    <label className="block mb-2">Window Size (seconds)</label>
                    <input 
                        type="number" 
                        name="window_size"
                        value={formData.window_size} 
                        onChange={handleInputChange}
                        className="bg-gray-600 p-2 rounded w-full" 
                    />
                </div>
                <div className="mb-4">
                    <label className="block mb-2">Data Retention (minutes)</label>
                    <input 
                        type="number" 
                        name="data_retention_minutes"
                        value={formData.data_retention_minutes} 
                        onChange={handleInputChange}
                        className="bg-gray-600 p-2 rounded w-full" 
                    />
                </div>
                <div className="mb-4">
                    <label className="block mb-2">Dashboard Update Interval (seconds)</label>
                    <input 
                        type="number" 
                        name="dashboard_update_interval"
                        value={formData.dashboard_update_interval} 
                        onChange={handleInputChange}
                        className="bg-gray-600 p-2 rounded w-full" 
                    />
                </div>
                <button 
                    onClick={handleSaveConfig}
                    className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-500"
                >
                    Save Settings
                </button>
            </div>
        </div>
    );
}, (prevProps, nextProps) => {
    return JSON.stringify(prevProps.config) === JSON.stringify(nextProps.config);
});

export default SettingsView;