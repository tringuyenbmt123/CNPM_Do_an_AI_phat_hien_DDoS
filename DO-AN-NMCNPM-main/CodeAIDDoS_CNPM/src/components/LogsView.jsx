import { memo, useState } from 'react';

const LogsView = memo(({ data }) => {
    const [severityFilter, setSeverityFilter] = useState("ALL");
    const [searchQuery, setSearchQuery] = useState("");
    const [showAttackOnly, setShowAttackOnly] = useState(false);

    const filteredLogs = data.recentAlerts.filter(alert => {
        const matchesSeverity = severityFilter === "ALL" || alert.severity === severityFilter;
        const matchesSearch = searchQuery === "" || 
            alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
            alert.time.toLowerCase().includes(searchQuery.toLowerCase()) ||
            alert.sourceIp.toLowerCase().includes(searchQuery.toLowerCase());
        const isAttackLog = !showAttackOnly || alert.isAttack;
        return matchesSeverity && matchesSearch && isAttackLog;
    });

    return (
        <div className="flex-1 p-6 bg-gray-800 text-white">
            <h1 className="text-3xl font-bold mb-6">Attack Logs</h1>
            <div className="bg-gray-700 p-4 rounded-lg">
                <div className="flex gap-4 mb-4 items-center">
                    <select 
                        className="bg-gray-600 p-2 rounded"
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                    >
                        <option>ALL</option>
                        <option>Critical</option>
                        <option>High</option>
                    </select>
                    <input 
                        type="text" 
                        placeholder="Search logs..." 
                        className="bg-gray-600 p-2 rounded flex-grow"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    <label className="flex items-center gap-2">
                        <input 
                            type="checkbox" 
                            checked={showAttackOnly}
                            onChange={(e) => setShowAttackOnly(e.target.checked)}
                            className="form-checkbox h-5 w-5 text-blue-600"
                        />
                        <span>Show attack logs only</span>
                    </label>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead>
                            <tr>
                                <th className="p-2">Timestamp</th>
                                <th className="p-2">Severity</th>
                                <th className="p-2">Source IP</th>
                                <th className="p-2">Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredLogs.length === 0 ? (
                                <tr>
                                    <td colSpan="4" className="p-2 text-center">
                                        No attack logs found
                                    </td>
                                </tr>
                            ) : (
                                filteredLogs.map((alert, index) => (
                                    <tr key={index} className="border-t border-gray-600 transition-all duration-500">
                                        <td className="p-2">{alert.time}</td>
                                        <td className={`p-2 ${alert.severity === "Critical" ? "text-red-500" : "text-orange-500"}`}>
                                            {alert.severity}
                                        </td>
                                        <td className="p-2">{alert.sourceIp}</td>
                                        <td className="p-2">{alert.description}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}, (prevProps, nextProps) => {
    return JSON.stringify(prevProps.data.recentAlerts) === JSON.stringify(nextProps.data.recentAlerts);
});

export default LogsView;