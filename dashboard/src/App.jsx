import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Info, CheckCircle, ShieldAlert, Cpu } from 'lucide-react';
import './App.css';

function App() {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const response = await fetch('http://localhost:8080/api/events');
        const data = await response.json();
        if (data) {
          setEvents(data);
        }
      } catch (error) {
        console.error('Error fetching events:', error);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 1000);
    return () => clearInterval(interval);
  }, []);

  const getIcon = (severity, type) => {
    if (type === 'AI_COPILOT' || type === 'AI_DECISION') return <Cpu size={20} />;
    switch (severity) {
      case 'critical': return <ShieldAlert size={20} />;
      case 'warning': return <AlertTriangle size={20} />;
      case 'success': return <CheckCircle size={20} />;
      default: return <Info size={20} />;
    }
  };

  return (
    <div className="dashboard-container">
      <header className="header glass-panel">
        <div className="logo-section">
          <Shield className="logo-icon" />
          <div>
            <h1 className="title">Sentinel-eBPF</h1>
            <p className="subtitle">Agentic Kernel Security Copilot</p>
          </div>
        </div>
        <div className="status-badge">
          <div className="status-dot"></div>
          ENGINE ACTIVE
        </div>
      </header>

      <main className="events-grid">
        {events.length === 0 ? (
          <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <Cpu size={48} style={{ opacity: 0.5, marginBottom: '1rem', margin: '0 auto' }} />
            <p>Awaiting telemetry events from kernel...</p>
          </div>
        ) : (
          events.map((event, index) => (
            <div key={`${event.timestamp}-${index}`} className="event-card glass-panel">
              <div className={`event-icon-wrapper icon-${event.severity}`}>
                {getIcon(event.severity, event.type)}
              </div>
              <div className="event-content">
                <div className="event-header">
                  <span className={`event-type type-${event.severity}`}>{event.type}</span>
                  <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="event-details">
                  {event.details}
                </div>
              </div>
            </div>
          ))
        )}
      </main>
    </div>
  );
}

export default App;
