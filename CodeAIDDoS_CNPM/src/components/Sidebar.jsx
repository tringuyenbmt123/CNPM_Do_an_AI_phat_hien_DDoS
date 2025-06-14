const Sidebar = ({ currentView, setCurrentView }) => (
    <div className="w-64 h-screen bg-gray-900 text-white p-4">
        <h1 className="text-xl font-bold mb-8">DASHBOARD</h1>
        <ul>
            {["Dashboard", "Logs", "Settings"].map(view => (
                <li
                    key={view}
                    className={`p-2 mb-2 cursor-pointer rounded transition-all duration-300 ${
                        currentView === view ? "bg-blue-600" : "bg-gray-800 hover:bg-gray-700"
                    }`}
                    onClick={() => setCurrentView(view)}
                >
                    {view}
                </li>
            ))}
        </ul>
    </div>
);

export default Sidebar;