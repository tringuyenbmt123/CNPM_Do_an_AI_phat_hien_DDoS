import { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import LogsView from './components/LogsView';
import SettingsView from './components/SettingsView';

const App = () => {
  const [currentView, setCurrentView] = useState('Dashboard');
  const [data, setData] = useState({
    totalTraffic: '0M',
    ddosAlerts: 0,
    detectedAttacks: 0,
    activeAttacks: 0,
    networkTraffic: { labels: [], bytes: [], alerts: [], attackPoints: [] },
    attackersByCountry: [],
    recentAlerts: [],
    ipList: [],
    logs: [],
    trainingData: [],
    settings: { trainingFrequency: 0, detectionThreshold: 0, aiModel: '' },
  });
  const [status, setStatus] = useState('Loading...');
  const [metrics, setMetrics] = useState({
    flow_bytes_s: 0,
    flow_packets_s: 0,
    unique_sources: 0,
    is_attack: false,
  });
  const [config, setConfig] = useState({
    interface: '',
    window_size: 1.0,
    data_retention_minutes: 10,
    dashboard_update_interval: 1,
  });
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const response = await fetch(`/api/combined_data?t=${Date.now()}`, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Cache-Control': 'no-cache',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      if (result.error) {
        throw new Error(result.error);
      }

      setData((prevData) => {
        const newData = {
          ...prevData,
          ...result.dashboard,
          networkTraffic: result.dashboard.networkTraffic || prevData.networkTraffic,
          attackersByCountry: result.dashboard.attackersByCountry || prevData.attackersByCountry,
          recentAlerts: result.dashboard.recentAlerts || prevData.recentAlerts,
          ipList: result.dashboard.ipList || prevData.ipList,
        };
        return JSON.stringify(newData) === JSON.stringify(prevData) ? prevData : newData;
      });

      setStatus(result.status || 'Normal');
      setMetrics(
        result.metrics || {
          flow_bytes_s: 0,
          flow_packets_s: 0,
          unique_sources: 0,
          is_attack: false,
        }
      );

      const configResponse = await fetch('/api/config', {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Cache-Control': 'no-cache',
        },
      });

      if (!configResponse.ok) {
        throw new Error(`HTTP error! status: ${configResponse.status}`);
      }

      const configResult = await configResponse.json();
      setConfig(configResult);
      setError(null);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError(error.message);
      setStatus('Error');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, config.dashboard_update_interval * 1000 || 5000);
    return () => clearInterval(interval);
  }, [fetchData, config.dashboard_update_interval]);

  const renderView = () => {
    if (error) {
      return (
        <div className="p-4">
          <h2 className="text-2xl text-red-600 mb-4">Error</h2>
          <p>{error}</p>
        </div>
      );
    }

    switch (currentView) {
      case 'Dashboard':
        return <DashboardView data={data} status={status} metrics={metrics} />;
      case 'Logs':
        return <LogsView data={data} />;
      case 'Settings':
        return <SettingsView data={data} config={config} setConfig={setConfig} />;
      default:
        return <DashboardView data={data} status={status} metrics={metrics} />;
    }
  };

  return (
    <div className="flex bg-gray-900 text-white min-h-screen">
      <Sidebar currentView={currentView} setCurrentView={setCurrentView} />
      {renderView()}
    </div>
  );
};

export default App;
