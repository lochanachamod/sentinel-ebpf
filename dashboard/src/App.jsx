import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  List, 
  FileCode2, 
  Cpu,
  AlertTriangle,
  ShieldAlert,
  Terminal,
  Server
} from 'lucide-react';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    totalEvents: 0,
    totalAnomalies: 0,
    totalAIInterventions: 0,
    totalKills: 0
  });
  const [config, setConfig] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [eventsRes, statsRes, configRes] = await Promise.all([
          fetch('http://localhost:8080/api/events'),
          fetch('http://localhost:8080/api/stats'),
          fetch('http://localhost:8080/api/config')
        ]);
        
        if (eventsRes.ok) setEvents(await eventsRes.json() || []);
        if (statsRes.ok) setStats(await statsRes.json());
        if (configRes.ok) setConfig(await configRes.json());
      } catch (error) {
        console.error('API Error:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  const renderContent = () => {
    switch (activeTab) {
      case 'overview': return <Overview stats={stats} events={events} />;
      case 'telemetry': return <Telemetry events={events} />;
      case 'policies': return <Policies config={config} />;
      default: return <Overview stats={stats} events={events} />;
    }
  };

  return (
    <div className="dashboard-layout">
      <aside className="sidebar">
        <div className="brand">
          <Shield className="brand-icon" size={28} />
          <h1>Sentinel-eBPF</h1>
        </div>
        
        <nav className="nav-links">
          <div 
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity size={20} />
            <span>Overview</span>
          </div>
          <div 
            className={`nav-item ${activeTab === 'telemetry' ? 'active' : ''}`}
            onClick={() => setActiveTab('telemetry')}
          >
            <List size={20} />
            <span>Live Telemetry</span>
          </div>
          <div 
            className={`nav-item ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <FileCode2 size={20} />
            <span>Security Policies</span>
          </div>
        </nav>

        <div className="system-status">
          <div className="status-header">
            <div className="status-dot"></div>
            ENGINE ACTIVE
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Kernel Probe Attached
          </span>
        </div>
      </aside>

      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}

// --- Pages ---

function Overview({ stats, events }) {
  const recentCritical = events.filter(e => e.severity === 'critical' || e.severity === 'warning').slice(0, 5);

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Command Center</h2>
        <p>High-level security overview and system metrics.</p>
      </div>

      <div className="metrics-grid">
        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span>Total Kernel Events</span>
            <Server size={18} />
          </div>
          <div className="metric-value info">{stats.totalEvents.toLocaleString()}</div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span>Anomalies Detected</span>
            <AlertTriangle size={18} />
          </div>
          <div className="metric-value critical">{stats.totalAnomalies.toLocaleString()}</div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span>AI Interventions</span>
            <Cpu size={18} />
          </div>
          <div className="metric-value">{stats.totalAIInterventions.toLocaleString()}</div>
        </div>
        <div className="metric-card glass-panel">
          <div className="metric-header">
            <span>Threats Contained</span>
            <ShieldAlert size={18} />
          </div>
          <div className="metric-value">{stats.totalKills.toLocaleString()}</div>
        </div>
      </div>

      <div className="glass-panel" style={{ marginTop: '2rem', padding: '1.5rem' }}>
        <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Recent Critical Alerts</h3>
        {recentCritical.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>No critical alerts in recent history.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {recentCritical.map((e, i) => (
              <div key={i} style={{ padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', borderLeft: `3px solid var(--${e.severity === 'critical' ? 'danger' : 'warning'})` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                  <strong style={{ fontSize: '0.85rem', color: `var(--${e.severity === 'critical' ? 'danger' : 'warning'})` }}>{e.type}</strong>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(e.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="mono" style={{ fontSize: '0.85rem' }}>{e.details}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Telemetry({ events }) {
  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Live Telemetry</h2>
        <p>Real-time stream of all hooked kernel syscalls.</p>
      </div>

      <div className="glass-panel data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                  Awaiting telemetry events...
                </td>
              </tr>
            ) : (
              events.map((e, i) => (
                <tr key={`${e.timestamp}-${i}`}>
                  <td style={{ whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ fontWeight: '600' }}>{e.type}</td>
                  <td>
                    <span className={`badge badge-${e.severity}`}>
                      {e.severity}
                    </span>
                  </td>
                  <td className="mono">{e.details}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Policies({ config }) {
  if (!config) return <div style={{ padding: '2rem' }}>Loading configuration...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Security Policies</h2>
        <p>Currently active YAML configurations and AI parameters.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
        
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
            <Cpu color="var(--accent)" />
            <h3 style={{ fontSize: '1.2rem' }}>AI Copilot Configuration</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Status</span>
              <span className={`badge badge-${config.ai_config?.enabled ? 'success' : 'warning'}`}>
                {config.ai_config?.enabled ? 'ENABLED' : 'DISABLED'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Endpoint</span>
              <span className="mono">{config.ai_config?.endpoint}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.5rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>API Key</span>
              <span className="mono">••••••••••••••••</span>
            </div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
            <Terminal color="var(--accent)" />
            <h3 style={{ fontSize: '1.2rem' }}>Active Rule Engine</h3>
          </div>
          <div className="yaml-container">
            <pre>
{`rules:
${config.rules?.map(r => `  - name: "${r.name}"
    action: "${r.action}"
    target_executables:
${r.target_executables.map(t => `      - "${t}"`).join('\n')}
    blocked_parents:
${r.blocked_parents.map(p => `      - "${p}"`).join('\n')}`).join('\n\n')}
`}
            </pre>
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
