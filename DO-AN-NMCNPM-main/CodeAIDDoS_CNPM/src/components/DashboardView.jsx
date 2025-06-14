import { useState, useEffect, useMemo, memo, useCallback, useRef } from 'react';
import Chart from 'chart.js/auto';
import { MatrixController, MatrixElement } from 'chartjs-chart-matrix';
import { BarController, BarElement, CategoryScale, LinearScale } from 'chart.js';
import { MapContainer, TileLayer, GeoJSON } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import debounce from 'lodash/debounce';

Chart.register(MatrixController, MatrixElement, BarController, BarElement, CategoryScale, LinearScale);

const useFetchConfig = (setError) => {
  const [config, setConfig] = useState({ dashboard_update_interval: 1 });

  useEffect(() => {
    const fetchConfig = async () => {
      try {
        const response = await fetch('/api/config', {
          method: 'GET',
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
        });
        if (response.ok) {
          const configData = await response.json();
          setConfig(configData);
        } else {
          const errorText = await response.text();
          setError(`Failed to fetch config: ${errorText}`);
        }
      } catch (error) {
        setError(`Error fetching config: ${error.message}`);
      }
    };
    fetchConfig();
  }, [setError]);

  return config;
};

const useGeoJson = (setError) => {
  const [countriesGeoJson, setCountriesGeoJson] = useState(null);

  useEffect(() => {
    const fetchGeoJson = async (retryCount = 3, delay = 2000) => {
      for (let attempt = 1; attempt <= retryCount; attempt++) {
        try {
          console.log(`[useGeoJson] Fetching GeoJSON from /dashboard/countries.geojson (Attempt ${attempt})`);
          const response = await fetch('/dashboard/countries.geojson', {
            headers: { 'Cache-Control': 'no-cache' },
          });
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
          const data = await response.json();
          console.log('[useGeoJson] GeoJSON loaded successfully:', data);
          setCountriesGeoJson(data);
          return;
        } catch (error) {
          console.error(`[useGeoJson] Error fetching GeoJSON (Attempt ${attempt}):`, error);
          if (attempt === retryCount) {
            setError(`Error fetching GeoJSON: ${error.message}`);
            setCountriesGeoJson({ type: 'FeatureCollection', features: [] });
          } else {
            console.log(`[useGeoJson] Retrying in ${delay}ms...`);
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      }
    };
    fetchGeoJson();
  }, [setError]);

  return countriesGeoJson;
};

const useAttackerCountries = (ipList, setError) => {
  const [attackerCountries, setAttackerCountries] = useState([]);
  const [ipCountryCache, setIpCountryCache] = useState({});

  const isPrivateIp = (ip) => ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.');

  const fetchCountry = useCallback(async (ip) => {
    if (isPrivateIp(ip)) return 'Local Network';
    if (ipCountryCache[ip]) return ipCountryCache[ip];
    try {
      const response = await fetch(`http://ip-api.com/json/${ip}`, {
        headers: { 'Cache-Control': 'no-cache' },
      });
      const data = await response.json();
      if (data.status === 'success') {
        setIpCountryCache((prev) => ({ ...prev, [ip]: data.country }));
        return data.country;
      }
      return 'Unknown';
    } catch (error) {
      setError(`Error fetching country for IP ${ip}: ${error.message}`);
      return 'Unknown';
    }
  }, [ipCountryCache, setError]);

  useEffect(() => {
    const updateAttackerCountries = async () => {
      const countries = [];
      for (const ipData of ipList || []) {
        if (ipData.isAttack) {
          const country = await fetchCountry(ipData.sourceIp);
          if (country && !countries.includes(country)) {
            countries.push(country);
          }
        }
      }
      setAttackerCountries(countries);
    };
    updateAttackerCountries();
  }, [ipList, fetchCountry]);

  return attackerCountries;
};

const DashboardView = memo(({ data, status, metrics }) => {
  const [chartInstance, setChartInstance] = useState(null);
  const [heatmapKey, setHeatmapKey] = useState(0);
  const [featureChartInstance, setFeatureChartInstance] = useState(null);
  const [heatmapData, setHeatmapData] = useState({ src_ips: [], dst_ips: [], z_values: [], blocked_ips: [] });
  const [featureImportance, setFeatureImportance] = useState({ features: [], importance: [] });
  const [heatmapError, setHeatmapError] = useState(null);
  const [featureError, setFeatureError] = useState(null);
  const [error, setError] = useState(null);
  const eventSourceRef = useRef(null);

  const config = useFetchConfig(setError);
  const countriesGeoJson = useGeoJson(setError);
  const attackerCountries = useAttackerCountries(data.ipList, setError);

  useEffect(() => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        for (let registration of registrations) {
          registration.unregister();
        }
      });
    }
  }, []);

  const chartData = useMemo(() => {
    const maxPoints = 50;
    const labels = (data.networkTraffic.labels || []).slice(-maxPoints);
    const bytes = (data.networkTraffic.bytes || []).slice(-maxPoints);
    const alerts = (data.networkTraffic.alerts || []).slice(-maxPoints);
    const attackPoints = (data.networkTraffic.attackPoints || []).filter((point) => labels.includes(point.time));

    return {
      labels,
      datasets: [
        {
          label: 'Bytes/s',
          data: bytes,
          borderColor: '#3b82f6',
          fill: false,
          tension: 0.1,
        },
        {
          label: 'Alerts',
          data: alerts,
          borderColor: '#ef4444',
          fill: false,
          tension: 0.1,
        },
        {
          label: 'Attack Points',
          data: attackPoints.map((point) => ({ x: point.time, y: point.value })),
          type: 'scatter',
          borderColor: '#ff0000',
          backgroundColor: '#ff0000',
          pointRadius: 6,
          pointHoverRadius: 8,
          showLine: false,
        },
      ],
    };
  }, [data.networkTraffic]);

  useEffect(() => {
    const ctx = document.getElementById('trafficChart')?.getContext('2d');
    if (!ctx) {
      setError('Traffic chart canvas not found');
      return;
    }

    const newChart = new Chart(ctx, {
      type: 'line',
      data: chartData,
      options: {
        scales: {
          y: { beginAtZero: true, ticks: { color: '#ffffff' } },
          x: { ticks: { color: '#ffffff', maxRotation: 45, minRotation: 45 } },
        },
        animation: { duration: 500, easing: 'easeInOutQuad' },
        plugins: {
          legend: { labels: { color: '#ffffff' } },
          annotation: {
            annotations: (data.networkTraffic.attackPoints || []).map((point) => ({
              type: 'box',
              xMin: point.time,
              xMax: point.time,
              yMin: 0,
              yMax: Math.max(...(data.networkTraffic.bytes || [0])) * 1.1,
              backgroundColor: 'rgba(255, 0, 0, 0.2)',
              borderColor: 'rgba(255, 0, 0, 0.5)',
              borderWidth: 1,
            })),
          },
        },
      },
    });
    setChartInstance(newChart);

    return () => newChart.destroy();
  }, []);

  useEffect(() => {
    if (chartInstance) {
      chartInstance.data = chartData;
      chartInstance.options.plugins.annotation.annotations = (data.networkTraffic.attackPoints || []).map((point) => ({
        type: 'box',
        xMin: point.time,
        xMax: point.time,
        yMin: 0,
        yMax: Math.max(...(data.networkTraffic.bytes || [0])) * 1.1,
        backgroundColor: 'rgba(255, 0, 0, 0.2)',
        borderColor: 'rgba(255, 0, 0, 0.5)',
        borderWidth: 1,
      }));
      chartInstance.update('none');
    }
  }, [chartData, chartInstance]);

  const HeatmapChart = ({ src_ips, dst_ips, z_values, blocked_ips }) => {
    const canvasRef = useRef(null);
    const chartInstanceRef = useRef(null);

    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy();
        chartInstanceRef.current = null;
      }
      const existing = Chart.getChart(canvas);
      if (existing) {
        existing.destroy();
      }

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const maxValue = z_values.length > 0 ? Math.max(...z_values.flat()) : 1;

      chartInstanceRef.current = new Chart(ctx, {
        type: 'matrix',
        data: {
          datasets: [
            {
              label: 'Packet Flow Heatmap',
              data: z_values.flatMap((row, y) =>
                row.map((value, x) => ({
                  x,
                  y,
                  v: value,
                  src: src_ips[y],
                  dst: dst_ips[x],
                  blocked: blocked_ips.includes(src_ips[y]),
                }))
              ),
              backgroundColor: (ctx) => {
                if (!ctx.raw) return 'rgba(0, 0, 0, 0)';
                const value = ctx.raw.v;
                const alpha = value / maxValue;
                return `rgba(46, 204, 113, ${alpha})`;
              },
              width: () => Math.max(20, 300 / dst_ips.length - 2),
              height: () => Math.max(20, 300 / src_ips.length - 2),
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              type: 'category',
              labels: dst_ips,
              ticks: { color: '#ffffff', maxRotation: 45, minRotation: 45 },
              title: { display: true, text: 'Destination IP', color: '#ffffff' },
            },
            y: {
              type: 'category',
              labels: src_ips,
              ticks: { color: '#ffffff' },
              title: { display: true, text: 'Source IP', color: '#ffffff' },
            },
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const { src, dst, v, blocked } = ctx.raw;
                  return `Src: ${src}\nDst: ${dst}\nPackets/s: ${v.toFixed(2)}${blocked ? '\nBLOCKED' : ''}`;
                },
              },
            },
          },
          animation: { duration: 300 },
        },
      });

      return () => {
        if (chartInstanceRef.current) {
          chartInstanceRef.current.destroy();
          chartInstanceRef.current = null;
        }
        const existing = Chart.getChart(canvas);
        if (existing) {
          existing.destroy();
        }
      };
    }, [src_ips, dst_ips, z_values, blocked_ips]);

    return <canvas ref={canvasRef} className="w-full h-full" />;
  };

  const updateHeatmap = useCallback(
    debounce((heatmapData) => {
      console.log('[updateHeatmap] Attempting to update heatmap:', heatmapData);
      if (!heatmapData || !heatmapData.src_ips || !heatmapData.dst_ips || !heatmapData.z_values) {
        console.warn('[updateHeatmap] Invalid heatmap data:', heatmapData);
        setHeatmapError('Invalid heatmap data received');
        return;
      }
      const { src_ips, dst_ips, z_values, blocked_ips = [] } = heatmapData;
      if (!Array.isArray(src_ips) || !Array.isArray(dst_ips) || !Array.isArray(z_values)) {
        console.warn('[updateHeatmap] Heatmap data format error:', heatmapData);
        setHeatmapError('Heatmap data format error');
        return;
      }
      try {
        setHeatmapData(heatmapData);
        setHeatmapKey(prevKey => prevKey + 1);
        setHeatmapError(null);
      } catch (error) {
        console.error('[updateHeatmap] Error updating heatmap:', error);
        setHeatmapError(`Error updating heatmap: ${error.message}`);
      }
    }, 900),
    []
  );

  const updateFeatures = useCallback(
    debounce((featureData) => {
      const { features, importance } = featureData;
      if (featureChartInstance) {
        featureChartInstance.data.labels = features;
        featureChartInstance.data.datasets[0].data = importance;
        featureChartInstance.data.datasets[0].backgroundColor = importance.map((val) =>
          val > 0.6 ? 'rgba(231, 76, 60, 0.8)' : 'rgba(52, 152, 219, 0.8)'
        );
        featureChartInstance.update('none');
        return;
      }

      const ctx = document.getElementById('featureChart')?.getContext('2d');
      if (!ctx) {
        setError('Feature chart canvas not found');
        return;
      }

      const newChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: features,
          datasets: [
            {
              label: 'Feature Importance',
              data: importance,
              backgroundColor: importance.map((val) =>
                val > 0.6 ? 'rgba(231, 76, 60, 0.8)' : 'rgba(52, 152, 219, 0.8)'
              ),
              borderColor: 'rgba(0, 0, 0, 0.2)',
              borderWidth: 1,
            },
          ],
        },
        options: {
          indexAxis: 'y',
          scales: {
            x: {
              beginAtZero: true,
              max: 1,
              ticks: { color: '#ffffff' },
              title: { display: true, text: 'Importance Score', color: '#ffffff' },
            },
            y: {
              ticks: { color: '#ffffff' },
            },
          },
          plugins: {
            legend: { display: false },
          },
          animation: { duration: 500, easing: 'easeInOutQuad' },
        },
      });
      setFeatureChartInstance(newChart);
    }, 500),
    [featureChartInstance]
  );

  useEffect(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    eventSourceRef.current = new EventSource('/api/stream');

    eventSourceRef.current.onmessage = (event) => {
      try {
        const streamData = JSON.parse(event.data);
        console.log('[SSE] Received stream data:', streamData);
        if (streamData.error) {
          console.warn('[SSE] Stream error:', streamData.error);
          setHeatmapError(streamData.error);
          setFeatureError(streamData.error);
          return;
        }

        if (streamData.heatmap) {
          console.log('[SSE] Heatmap data received:', streamData.heatmap);
          if (streamData.heatmap.src_ips && streamData.heatmap.src_ips.length > 0) {
            console.log('[SSE] Updating heatmap with data:', streamData.heatmap);
            setHeatmapData(streamData.heatmap);
            updateHeatmap(streamData.heatmap);
            setHeatmapError(null);
          } else {
            console.log('[SSE] Heatmap data is empty or invalid, skipping update');
          }
        } else {
          console.log('[SSE] No heatmap data in stream');
        }

        if (streamData.features) {
          console.log('[SSE] Updating feature importance with data:', streamData.features);
          setFeatureImportance(streamData.features);
          updateFeatures(streamData.features);
          setFeatureError(null);
        }
      } catch (e) {
        console.error('[SSE] Error processing stream data:', e);
        setHeatmapError('Error processing real-time data');
        setFeatureError('Error processing real-time data');
      }
    };

    eventSourceRef.current.onerror = () => {
      console.warn('[SSE] Connection lost, attempting to reconnect...');
      setHeatmapError('SSE connection lost');
      setFeatureError('SSE connection lost');
      setTimeout(() => {
        if (eventSourceRef.current) {
          eventSourceRef.current.close();
          eventSourceRef.current = new EventSource('/api/stream');
        }
      }, 5000);
    };

    return () => {
      console.log('[SSE] Closing SSE connection');
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      updateHeatmap.cancel();
      updateFeatures.cancel();
    };
  }, [updateHeatmap, updateFeatures]);

  const handleBlockIP = useCallback(async (ip) => {
    try {
      const response = await fetch('/api/block_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
        body: JSON.stringify({ ip }),
      });
      const result = await response.json();
      if (result.success) {
        showNotification(result.message, 'success');
      } else {
        showNotification(result.message || 'Failed to block IP', 'error');
      }
    } catch (error) {
      showNotification('Failed to block IP', 'error');
      setError(`Error blocking IP: ${error.message}`);
    }
  }, [setError]);

  const handleUnblockIP = useCallback(
    async (ip) => {
      try {
        const response = await fetch('/api/unblock', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
          body: JSON.stringify({ ip }),
        });

        const result = await response.json();

        if (result.status === 'success') {
          showNotification(result.message, 'success');
        } else {
          showNotification(result.message || 'Failed to unblock IP', 'error');
        }
      } catch (error) {
        showNotification('Failed to unblock IP', 'error');
        setError(`Error unblockIP: ${error.message}`);
      }
    },
    [setError]
  );

  const countryNameMapping = {
    'United States': 'United States of America',
    'Germany': 'Germany',
  };

  const mappedAttackerCountries = attackerCountries.map((country) => countryNameMapping[country] || country);

  const geoJsonStyle = (feature) => ({
    color: mappedAttackerCountries.includes(feature.properties.name) ? 'red' : 'gray',
    weight: mappedAttackerCountries.includes(feature.properties.name) ? 2 : 1,
    fillOpacity: mappedAttackerCountries.includes(feature.properties.name) ? 0.5 : 0,
  });

  const onEachFeature = (feature, layer) => {
    if (mappedAttackerCountries.includes(feature.properties.name)) {
      layer.bindTooltip(feature.properties.name, { sticky: true });
    }
  };

  return (
    <div className="flex-1 p-6 bg-gray-800 text-white min-h-screen">
      <h1 className="text-3xl font-bold mb-6">AI-Based DDoS Detection</h1>
      {error && (
        <div className="bg-red-600 p-4 rounded-lg mb-6">
          <p className="text-lg font-semibold">Error: {error}</p>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold">Total Traffic</h2>
          <p className="text-3xl">{data.totalTraffic || 'N/A'}</p>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold">DDoS Alerts</h2>
          <p className="text-3xl">{data.ddosAlerts || 0}</p>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold">Detected Attacks</h2>
          <p className="text-3xl">{data.detectedAttacks || 0}</p>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold">Active Attacks</h2>
          <p className="text-3xl">{data.activeAttacks || 0}</p>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">Network Traffic / DDoS Alerts</h2>
          <canvas id="trafficChart" className="w-full h-80"></canvas>
        </div>
        <div className="flex flex-col gap-6">
          <div className={`p-4 rounded-lg ${status === 'Under Attack' ? 'bg-red-600' : 'bg-gray-700'}`}>
            <h2 className="text-lg font-semibold">System Status</h2>
            <p className="text-3xl">{status}</p>
          </div>
          <div className="bg-gray-700 p-4 rounded-lg flex-1">
            <h2 className="text-lg font-semibold">Metrics</h2>
            <p>Flow Bytes/s: {(metrics.flow_bytes_s || 0).toFixed(2)}</p>
            <p>Flow Packets/s: {(metrics.flow_packets_s || 0).toFixed(2)}</p>
            <p>Unique Sources: {metrics.unique_sources || 'N/A'}</p>
            <p>Attack Detected: {metrics.is_attack ? 'Yes' : 'No'}</p>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">Attackers by Country</h2>
          <MapContainer
            center={[0, 0]}
            zoom={2}
            style={{ height: '400px', width: '100%', background: '#1a202c' }}
            className="rounded-lg"
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors © <a href="https://carto.com/attributions">CARTO</a>'
              subdomains="abcd"
              maxZoom={19}
            />
            {countriesGeoJson && (
              <GeoJSON data={countriesGeoJson} style={geoJsonStyle} onEachFeature={onEachFeature} />
            )}
          </MapContainer>
          <div className="mt-4">
            <ul className="flex gap-4 flex-wrap">
              {attackerCountries.length > 0 ? (
                attackerCountries.map((country, index) => (
                  <li key={index} className="flex items-center">
                    <div className="w-4 h-4 rounded-full bg-red-500 mr-2"></div>
                    <span>{country}</span>
                  </li>
                ))
              ) : (
                <li>No attacking countries detected</li>
              )}
            </ul>
          </div>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">Recent Alerts</h2>
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th className="p-2">Time</th>
                  <th className="p-2">Severity</th>
                  <th className="p-2">Source IP</th>
                  <th className="p-2">Description</th>
                </tr>
              </thead>
              <tbody>
                {(data.recentAlerts || []).map((alert, index) => (
                  <tr key={index} className="border-t border-gray-600">
                    <td className="p-2">{alert.time || 'N/A'}</td>
                    <td
                      className={`p-2 ${alert.severity === 'Critical'
                        ? 'text-red-500'
                        : alert.severity === 'High'
                          ? 'text-orange-500'
                          : 'text-yellow-500'
                        }`}
                    >
                      {alert.severity || 'N/A'}
                    </td>
                    <td className="p-2">{alert.sourceIp || 'N/A'}</td>
                    <td className="p-2">{alert.description || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">IP List</h2>
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th className="p-2">IP Address</th>
                  <th className="p-2">Connections</th>
                  <th className="p-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {(data.ipList || []).length > 0 ? (
                  data.ipList.map((ipData, index) => (
                    <tr key={index} className="border-t border-gray-600">
                      <td className="p-2">{ipData.sourceIp}</td>
                      <td className="p-2">{ipData.connections || 'N/A'}</td>
                      <td className="p-2">
                        {ipData.isAttack ? (
                          <>
                            <span className="text-red-500 mr-2">Blocked</span>
                            <button
                              onClick={() => handleUnblockIP(ipData.sourceIp)}
                              className="bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-500"
                            >
                              Unblock
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => handleBlockIP(ipData.sourceIp)}
                            className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-500"
                          >
                            Block
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="3" className="p-2 text-center">
                      No IPs detected
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">Packet Flow Heatmap</h2>
          {heatmapError ? (
            <p className="text-red-500">{heatmapError}</p>
          ) : heatmapData.src_ips.length > 0 ? (
            <div>
              <HeatmapChart
                src_ips={heatmapData.src_ips}
                dst_ips={heatmapData.dst_ips}
                z_values={heatmapData.z_values}
                blocked_ips={heatmapData.blocked_ips}
              />
            </div>
          ) : (
            <p className="text-gray-400">Waiting for sufficient data to display heatmap...</p>
          )}
        </div>
        <div className="bg-gray-700 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-4">Feature Importance</h2>
          {featureError ? (
            <p className="text-red-500">{featureError}</p>
          ) : featureImportance.features.length > 0 ? (
            <canvas id="featureChart" className="w-full h-80"></canvas>
          ) : (
            <p className="text-gray-400">No data available for feature importance</p>
          )}
        </div>
      </div>
    </div>
  );
}, (prevProps, nextProps) => {
  return (
    prevProps.data.totalTraffic === nextProps.data.totalTraffic &&
    prevProps.data.ddosAlerts === nextProps.data.ddosAlerts &&
    prevProps.data.detectedAttacks === nextProps.data.detectedAttacks &&
    prevProps.data.activeAttacks === nextProps.data.activeAttacks &&
    prevProps.status === nextProps.status &&
    JSON.stringify(prevProps.metrics) === JSON.stringify(nextProps.metrics) &&
    JSON.stringify(prevProps.data.networkTraffic) === JSON.stringify(nextProps.data.networkTraffic) &&
    JSON.stringify(prevProps.data.recentAlerts) === JSON.stringify(nextProps.data.recentAlerts) &&
    JSON.stringify(prevProps.data.ipList) === JSON.stringify(nextProps.data.ipList)
  );
});

export default DashboardView;