// ============================================================================
// PhantomScope — components/index.tsx
// All auxiliary UI components
// ============================================================================

import React, { useState, useRef, useEffect } from 'react';
import { useScanStore, ThreatLevel } from '../store/scanStore';

// ============================================================================
// TitleBar — Custom window chrome
// ============================================================================
export const TitleBar: React.FC = () => {
  const { isScanning, scanProgress } = useScanStore();
  const api = (window as any).phantomAPI;
  const isElectron = !!api;

  return (
    <div className="titlebar">
      <div className="titlebar-drag-region" />

      <div className="titlebar-left">
        <div className="app-logo">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <circle cx="10" cy="10" r="9" stroke="#0A84FF" strokeWidth="1.5"/>
            <circle cx="10" cy="10" r="5" stroke="#0A84FF" strokeWidth="1" opacity="0.5"/>
            <circle cx="10" cy="10" r="2" fill="#0A84FF"/>
            <circle cx="10" cy="3"  r="1.5" fill="#FF2D55"/>
            <circle cx="17" cy="10" r="1.5" fill="#30D158"/>
            <circle cx="10" cy="17" r="1.5" fill="#FF9F0A"/>
            <circle cx="3"  cy="10" r="1.5" fill="#0A84FF"/>
          </svg>
        </div>
        <span className="app-name">PhantomScope</span>
        {isScanning && (
          <div className="titlebar-scan-status">
            <div className="scan-pulse" />
            <span>{scanProgress.message}</span>
          </div>
        )}
      </div>

      {isElectron && (
        <div className="titlebar-controls">
          <button className="wc-btn wc-minimize"
                  onClick={() => api.minimizeWindow()}
                  title="Minimize">
            <svg width="10" height="1" viewBox="0 0 10 1"><path d="M0 0h10v1H0z" fill="currentColor"/></svg>
          </button>
          <button className="wc-btn wc-maximize"
                  onClick={() => api.maximizeWindow()}
                  title="Maximize">
            <svg width="10" height="10" viewBox="0 0 10 10"><rect width="9" height="9" x=".5" y=".5" fill="none" stroke="currentColor"/></svg>
          </button>
          <button className="wc-btn wc-close"
                  onClick={() => api.closeWindow()}
                  title="Close">
            <svg width="10" height="10" viewBox="0 0 10 10"><path d="M0 0l10 10M10 0L0 10" stroke="currentColor" strokeWidth="1.2"/></svg>
          </button>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// SideNav — Navigation sidebar with scan trigger
// ============================================================================
export const SideNav: React.FC = () => {
  const { activeView, setActiveView, isScanning, startScan, graphData } = useScanStore();

  const navItems = [
    {
      id: 'graph', label: 'Graph',
      icon: (
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
          <circle cx="9" cy="9" r="2.5" stroke="currentColor" strokeWidth="1.5"/>
          <circle cx="3" cy="9" r="1.5" stroke="currentColor" strokeWidth="1.2"/>
          <circle cx="15" cy="9" r="1.5" stroke="currentColor" strokeWidth="1.2"/>
          <circle cx="9" cy="3" r="1.5" stroke="currentColor" strokeWidth="1.2"/>
          <circle cx="9" cy="15" r="1.5" stroke="currentColor" strokeWidth="1.2"/>
          <path d="M5 9h1.5M11.5 9H13M9 5v1.5M9 11.5V13" stroke="currentColor" strokeWidth="1.2"/>
        </svg>
      ),
    },
    {
      id: 'dashboard', label: 'Dashboard',
      icon: (
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
          <rect x="2" y="2" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
          <rect x="10" y="2" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
          <rect x="2" y="10" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
          <rect x="10" y="10" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.2"/>
        </svg>
      ),
    },
    {
      id: 'inspector', label: 'Inspector',
      icon: (
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
          <circle cx="8" cy="8" r="5" stroke="currentColor" strokeWidth="1.5"/>
          <path d="M12 12l4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      ),
    },
    {
      id: 'history', label: 'History',
      icon: (
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
          <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5"/>
          <path d="M9 5v4.5l2.5 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      ),
    },
    {
      id: 'settings', label: 'Settings',
      icon: (
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
          <circle cx="9" cy="9" r="2.5" stroke="currentColor" strokeWidth="1.5"/>
          <path d="M9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.7 3.7l1.4 1.4M12.9 12.9l1.4 1.4M3.7 14.3l1.4-1.4M12.9 5.1l1.4-1.4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      ),
    },
  ] as const;

  const criticalCount = graphData?.stats.criticalCount || 0;

  return (
    <nav className="sidenav">
      {/* Scan button */}
      <div className="sidenav-scan">
        <button
          className={`scan-btn ${isScanning ? 'scanning' : ''}`}
          onClick={() => isScanning ? useScanStore.getState().stopScan() : startScan()}
          title={isScanning ? 'Stop Scan' : 'Start Scan'}
        >
          {isScanning ? (
            <>
              <div className="scan-spinner" />
              <span>STOP</span>
            </>
          ) : (
            <>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.5"/>
                <path d="M8 4v4.5l3 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
              <span>SCAN</span>
            </>
          )}
        </button>
      </div>

      <div className="sidenav-divider" />

      {/* Nav items */}
      {navItems.map(item => (
        <button
          key={item.id}
          className={`nav-item ${activeView === item.id ? 'active' : ''}`}
          onClick={() => setActiveView(item.id as any)}
          title={item.label}
        >
          {item.icon}
          <span className="nav-label">{item.label}</span>
          {item.id === 'graph' && criticalCount > 0 && (
            <span className="nav-badge">{criticalCount}</span>
          )}
        </button>
      ))}

      <div className="sidenav-bottom">
        <div className="platform-badge">
          {(window as any).phantomAPI?.platform === 'win32' ? 'WIN64' : 'LINUX64'}
        </div>
        <div className="version-badge">v1.0.0</div>
      </div>
    </nav>
  );
};

// ============================================================================
// ScanProgress — Overlay progress indicator
// ============================================================================
export const ScanProgress: React.FC = () => {
  const { scanProgress, stopScan } = useScanStore();

  const phaseOrder = ['processes', 'files', 'virustotal', 'graph'];
  const currentPhaseIdx = phaseOrder.indexOf(scanProgress.phase);

  return (
    <div className="scan-progress-overlay">
      <div className="scan-progress-card">
        <div className="scan-progress-header">
          <div className="scan-radar">
            <div className="radar-ring r1" />
            <div className="radar-ring r2" />
            <div className="radar-ring r3" />
            <div className="radar-dot" />
            <div className="radar-sweep" />
          </div>
          <div>
            <h3>Scanning System</h3>
            <p>{scanProgress.message}</p>
          </div>
        </div>

        <div className="scan-phases">
          {['Process Enum', 'File Scan', 'VirusTotal', 'Graph Build'].map((phase, i) => (
            <div
              key={phase}
              className={`phase-item ${i < currentPhaseIdx ? 'done' : i === currentPhaseIdx ? 'active' : 'pending'}`}
            >
              <div className="phase-dot">
                {i < currentPhaseIdx ? (
                  <svg width="10" height="10" viewBox="0 0 10 10">
                    <path d="M2 5l2.5 2.5L8 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
                  </svg>
                ) : i === currentPhaseIdx ? (
                  <div className="phase-spinner" />
                ) : null}
              </div>
              <span>{phase}</span>
            </div>
          ))}
        </div>

        {scanProgress.vtTotal && (
          <div className="scan-vt-progress">
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${((scanProgress.vtCompleted || 0) / scanProgress.vtTotal) * 100}%` }}
              />
            </div>
            <span>{scanProgress.vtCompleted || 0}/{scanProgress.vtTotal} hashes</span>
          </div>
        )}

        <button className="btn-stop" onClick={stopScan}>
          Abort Scan
        </button>
      </div>
    </div>
  );
};

// ============================================================================
// ThreatPanel — Right sidebar showing critical/suspicious nodes
// ============================================================================
export const ThreatPanel: React.FC = () => {
  const { graphData, selectNode, setActiveView, filterLevel, setFilterLevel } = useScanStore();

  const threatNodes = (graphData?.elements.nodes || [])
    .filter(n => n.data.threatLevel === 'critical' || n.data.threatLevel === 'suspicious')
    .sort((a, b) => b.data.score - a.data.score);

  const colorMap: Record<string, string> = {
    critical:   '#FF2D55',
    suspicious: '#FF9F0A',
  };

  return (
    <aside className="threat-panel">
      <div className="threat-panel-header">
        <h3>Threats</h3>
        <div className="threat-filter-pills">
          {(['all', 'critical', 'suspicious'] as const).map(level => (
            <button
              key={level}
              className={`pill ${filterLevel === level ? 'active' : ''}`}
              onClick={() => setFilterLevel(level as any)}
            >
              {level === 'all' ? 'ALL' : level.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="threat-list">
        {threatNodes.length === 0 && (
          <div className="threat-empty">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <circle cx="16" cy="16" r="14" fill="#30D15815"/>
              <path d="M10 16l4 4 8-8" stroke="#30D158" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <p>No active threats detected</p>
          </div>
        )}

        {threatNodes.map(node => {
          const color = colorMap[node.data.threatLevel] || '#636366';
          return (
            <div
              key={node.data.id}
              className="threat-item"
              style={{ '--threat-color': color } as React.CSSProperties}
              onClick={() => {
                selectNode({ id: node.data.id, data: node.data });
                setActiveView('inspector');
              }}
            >
              <div className="threat-item-dot" style={{ background: color }} />
              <div className="threat-item-body">
                <span className="threat-item-name">{node.data.name}</span>
                {node.data.isHidden && (
                  <span className="threat-tag hidden-tag">HIDDEN</span>
                )}
                {node.data.vtDetections != null && node.data.vtDetections > 0 && (
                  <span className="threat-tag vt-tag">VT:{node.data.vtDetections}</span>
                )}
                {node.data.entropy != null && node.data.entropy > 6.5 && (
                  <span className="threat-tag entropy-tag">H:{node.data.entropy.toFixed(1)}</span>
                )}
              </div>
              <div className="threat-score" style={{ color }}>
                {node.data.score}
              </div>
            </div>
          );
        })}
      </div>
    </aside>
  );
};

// ============================================================================
// QueryBar — Cypher-style graph filter input
// ============================================================================
export const QueryBar: React.FC = () => {
  const { searchQuery, setSearchQuery } = useScanStore();
  const inputRef = useRef<HTMLInputElement>(null);

  const QUICK_QUERIES = [
    { label: 'Hidden', query: 'MATCH (n:PHHiddenProcess) RETURN n' },
    { label: 'Critical', query: 'MATCH (n {threatLevel: "critical"}) RETURN n' },
    { label: 'VT Hits', query: 'MATCH (n {vtDetections > 0}) RETURN n' },
    { label: 'Unsigned', query: 'MATCH (n {isSigned: false}) RETURN n' },
    { label: 'High Entropy', query: 'MATCH (n {entropy > 6.5}) RETURN n' },
  ];

  return (
    <div className="query-bar">
      <div className="query-input-wrap">
        <svg className="query-icon" width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M2 2h10M2 5h7M2 8h5M2 11h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
        </svg>
        <input
          ref={inputRef}
          type="text"
          className="query-input"
          placeholder="MATCH (n:PHHiddenProcess) RETURN n   or type to search..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
        />
        {searchQuery && (
          <button className="query-clear" onClick={() => setSearchQuery('')}>
            <svg width="12" height="12" viewBox="0 0 12 12">
              <path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
          </button>
        )}
      </div>

      <div className="query-shortcuts">
        {QUICK_QUERIES.map(q => (
          <button
            key={q.label}
            className={`query-chip ${searchQuery === q.query ? 'active' : ''}`}
            onClick={() => setSearchQuery(searchQuery === q.query ? '' : q.query)}
          >
            {q.label}
          </button>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// ContextMenu — Right-click node menu
// ============================================================================
export const ContextMenu: React.FC<{
  x: number; y: number;
  nodeData: any;
  onClose: () => void;
}> = ({ x, y, nodeData, onClose }) => {
  const api = (window as any).phantomAPI;

  const actions = [
    {
      label: 'Scan Now',
      icon: '⚡',
      action: () => { api?.scanSingleFile(nodeData.path); onClose(); }
    },
    {
      label: 'VT Lookup',
      icon: '🔍',
      action: () => {
        if (nodeData.md5) {
          window.open(`https://www.virustotal.com/gui/file/${nodeData.md5}`, '_blank');
        }
        onClose();
      },
      disabled: !nodeData.md5,
    },
    {
      label: 'Copy MD5',
      icon: '📋',
      action: () => {
        if (nodeData.md5) navigator.clipboard.writeText(nodeData.md5);
        onClose();
      },
      disabled: !nodeData.md5,
    },
    {
      label: 'Copy Path',
      icon: '📁',
      action: () => {
        if (nodeData.path) navigator.clipboard.writeText(nodeData.path);
        onClose();
      },
      disabled: !nodeData.path,
    },
    {
      label: 'Open in Explorer',
      icon: '🗂',
      action: () => { api?.openFileInExplorer(nodeData.path); onClose(); },
      disabled: !nodeData.path,
    },
    { divider: true },
    {
      label: 'View Inspector',
      icon: '🔬',
      action: () => {
        useScanStore.getState().selectNode({ id: nodeData.id, data: nodeData });
        useScanStore.getState().setActiveView('inspector');
        onClose();
      },
    },
  ];

  return (
    <>
      <div className="context-overlay" onClick={onClose} />
      <div className="context-menu" style={{ left: x, top: y }}>
        <div className="context-header">{nodeData.name}</div>
        {actions.map((action, i) =>
          (action as any).divider
            ? <div key={i} className="context-divider" />
            : (
              <button
                key={action.label}
                className={`context-item ${(action as any).disabled ? 'disabled' : ''}`}
                onClick={(action as any).disabled ? undefined : action.action}
              >
                <span className="context-icon">{action.icon}</span>
                <span>{action.label}</span>
              </button>
            )
        )}
      </div>
    </>
  );
};

// ============================================================================
// FileInspector — Side panel for selected node detail
// ============================================================================
export const FileInspector: React.FC = () => {
  const { selectedNode } = useScanStore();
  const [vtResult, setVtResult] = useState<any>(null);
  const [isLoadingVT, setIsLoadingVT] = useState(false);

  const api = (window as any).phantomAPI;

  const handleVTLookup = async () => {
    if (!selectedNode?.data.md5) return;
    setIsLoadingVT(true);
    try {
      const result = await api?.vtLookup(selectedNode.data.md5);
      setVtResult(result);
    } catch (err) {
      console.error('VT lookup failed', err);
    } finally {
      setIsLoadingVT(false);
    }
  };

  if (!selectedNode) {
    return (
      <div className="inspector-empty">
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="22" stroke="#1C1C28" strokeWidth="1.5"/>
          <circle cx="20" cy="20" r="9" stroke="#2C2C3E" strokeWidth="1.5"/>
          <path d="M27 27l8 8" stroke="#2C2C3E" strokeWidth="2" strokeLinecap="round"/>
        </svg>
        <h3>No node selected</h3>
        <p>Click a node in the graph to inspect its details.</p>
      </div>
    );
  }

  const data = selectedNode.data;
  const threatColor: Record<string, string> = {
    critical: '#FF2D55', suspicious: '#FF9F0A',
    informational: '#0A84FF', clean: '#30D158',
  };

  const entropy = data.entropy || 0;
  const entropyPercent = (entropy / 8.0) * 100;
  const entropyColor = entropy > 7.5 ? '#FF2D55' : entropy > 6.5 ? '#FF9F0A' : '#30D158';

  return (
    <div className="file-inspector">
      <div className="inspector-header">
        <div className="inspector-node-icon" style={{ background: data.color + '20', borderColor: data.color }}>
          <div className="node-dot" style={{ background: data.color }} />
        </div>
        <div className="inspector-title">
          <h2>{data.name || 'Unknown'}</h2>
          <span className="node-type-badge">{data.type}</span>
        </div>
        <div
          className="threat-level-badge"
          style={{ background: (threatColor[data.threatLevel] || '#636366') + '20',
                   color: threatColor[data.threatLevel] || '#636366',
                   borderColor: threatColor[data.threatLevel] || '#636366' }}
        >
          {(data.threatLevel || 'unknown').toUpperCase()}
        </div>
      </div>

      {/* Threat Score */}
      <div className="inspector-section">
        <h4>Threat Score</h4>
        <div className="score-bar-wrap">
          <div className="score-bar">
            <div
              className="score-fill"
              style={{
                width: `${data.score}%`,
                background: `linear-gradient(90deg, #0A84FF, ${threatColor[data.threatLevel] || '#0A84FF'})`,
              }}
            />
          </div>
          <span className="score-number" style={{ color: threatColor[data.threatLevel] }}>
            {data.score}/100
          </span>
        </div>
      </div>

      {/* Path */}
      {data.path && (
        <div className="inspector-section">
          <h4>File Path</h4>
          <div className="inspector-path">
            <code>{data.path}</code>
            <button
              className="copy-btn"
              onClick={() => navigator.clipboard.writeText(data.path || '')}
              title="Copy path"
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <rect x="1" y="3" width="7" height="8" rx="1" stroke="currentColor" strokeWidth="1.2"/>
                <path d="M4 3V2a1 1 0 011-1h5a1 1 0 011 1v8a1 1 0 01-1 1H9" stroke="currentColor" strokeWidth="1.2"/>
              </svg>
            </button>
          </div>
        </div>
      )}

      {/* MD5 */}
      {data.md5 && (
        <div className="inspector-section">
          <h4>MD5 Hash</h4>
          <div className="inspector-hash">
            <code>{data.md5}</code>
            <button
              className="copy-btn"
              onClick={() => navigator.clipboard.writeText(data.md5 || '')}
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <rect x="1" y="3" width="7" height="8" rx="1" stroke="currentColor" strokeWidth="1.2"/>
                <path d="M4 3V2a1 1 0 011-1h5a1 1 0 011 1v8a1 1 0 01-1 1H9" stroke="currentColor" strokeWidth="1.2"/>
              </svg>
            </button>
          </div>
        </div>
      )}

      {/* Entropy gauge */}
      {data.entropy != null && (
        <div className="inspector-section">
          <h4>Shannon Entropy</h4>
          <div className="entropy-gauge">
            <div className="entropy-track">
              <div
                className="entropy-fill"
                style={{ width: `${entropyPercent}%`, background: entropyColor }}
              />
              <div
                className="entropy-threshold"
                style={{ left: `${(6.5 / 8.0) * 100}%` }}
                title="6.5 suspicious threshold"
              />
              <div
                className="entropy-threshold high"
                style={{ left: `${(7.5 / 8.0) * 100}%` }}
                title="7.5 encrypted threshold"
              />
            </div>
            <span style={{ color: entropyColor }}>H = {entropy.toFixed(4)}</span>
          </div>
          <span className="entropy-label" style={{ color: entropyColor }}>
            {entropy > 7.5 ? '⚠ Likely encrypted' :
             entropy > 6.5 ? '⚠ Possibly packed' :
             '✓ Normal entropy'}
          </span>
        </div>
      )}

      {/* PID info for processes */}
      {data.pid != null && data.pid > 0 && (
        <div className="inspector-section">
          <h4>Process Info</h4>
          <div className="inspector-kv">
            <div className="kv-row"><span>PID</span><code>{data.pid}</code></div>
            <div className="kv-row"><span>PPID</span><code>{data.ppid}</code></div>
            {data.isHidden && (
              <div className="kv-row">
                <span>Status</span>
                <span className="hidden-badge">HIDDEN FROM USER-MODE</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Signature status */}
      <div className="inspector-section">
        <h4>Digital Signature</h4>
        <div className={`sig-badge ${data.isSigned ? 'signed' : 'unsigned'}`}>
          {data.isSigned
            ? <><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 6l3 3 5-5" stroke="#30D158" strokeWidth="1.5" strokeLinecap="round"/></svg> Signed</>
            : <><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 2l8 8M10 2L2 10" stroke="#FF2D55" strokeWidth="1.5" strokeLinecap="round"/></svg> Unsigned</>
          }
        </div>
      </div>

      {/* VirusTotal */}
      <div className="inspector-section">
        <div className="section-header-row">
          <h4>VirusTotal</h4>
          {data.md5 && (
            <button
              className="btn-sm"
              onClick={handleVTLookup}
              disabled={isLoadingVT}
            >
              {isLoadingVT ? 'Checking...' : 'Lookup'}
            </button>
          )}
        </div>

        {data.vtDetections != null && data.vtDetections >= 0 && (
          <div className={`vt-result ${data.vtDetections > 0 ? 'vt-detected' : 'vt-clean'}`}>
            <span className="vt-count">{data.vtDetections}</span>
            <span>/{data.vtDetections >= 0 ? '72' : '—'} engines</span>
          </div>
        )}

        {vtResult && !vtResult.error && (
          <div className="vt-detail">
            {vtResult.threatName && (
              <div className="kv-row">
                <span>Threat</span>
                <code style={{ color: '#FF2D55' }}>{vtResult.threatName}</code>
              </div>
            )}
            <div className="kv-row">
              <span>Malicious</span><code>{vtResult.malicious ?? 0}</code>
            </div>
            <div className="kv-row">
              <span>Suspicious</span><code>{vtResult.suspicious ?? 0}</code>
            </div>
          </div>
        )}

        {!data.md5 && (
          <span className="inspector-na">No MD5 — cannot query VT</span>
        )}
      </div>

      {/* External link */}
      {data.md5 && (
        <a
          href={`https://www.virustotal.com/gui/file/${data.md5}`}
          target="_blank"
          rel="noreferrer"
          className="inspector-external-link"
        >
          Open in VirusTotal ↗
        </a>
      )}
    </div>
  );
};

// ============================================================================
// SettingsPanel — API key, scan options, export
// ============================================================================
export const SettingsPanel: React.FC = () => {
  const { hasApiKey, setHasApiKey } = useScanStore();
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  const api = (window as any).phantomAPI;

  const handleSaveKey = async () => {
    if (!api || !apiKeyInput.trim()) return;
    setSaveStatus('saving');
    try {
      const result = await api.setApiKey(apiKeyInput.trim());
      if (result.success) {
        setSaveStatus('saved');
        setHasApiKey(true);
        setApiKeyInput('');
        setTimeout(() => setSaveStatus('idle'), 2000);
      } else {
        setSaveStatus('error');
      }
    } catch {
      setSaveStatus('error');
    }
  };

  const handleClearKey = async () => {
    if (!api) return;
    await api.clearApiKey();
    setHasApiKey(false);
  };

  return (
    <div className="settings-panel">
      <div className="settings-header">
        <h1>Settings</h1>
      </div>

      <div className="settings-section">
        <h3>VirusTotal API Key</h3>
        <p className="settings-desc">
          Required for hash lookups. Get a free key at{' '}
          <a href="https://www.virustotal.com" target="_blank" rel="noreferrer">
            virustotal.com
          </a>
          . Stored securely in OS credential manager (never in config files).
        </p>

        {hasApiKey ? (
          <div className="api-key-status">
            <div className="key-set-indicator">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M2 7l4 4 6-6" stroke="#30D158" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
              API key configured
            </div>
            <button className="btn-danger-sm" onClick={handleClearKey}>
              Remove Key
            </button>
          </div>
        ) : (
          <div className="api-key-input-row">
            <input
              type="password"
              className="settings-input"
              placeholder="Enter VirusTotal API key..."
              value={apiKeyInput}
              onChange={e => setApiKeyInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSaveKey()}
            />
            <button
              className={`btn-primary ${saveStatus === 'saving' ? 'loading' : ''}`}
              onClick={handleSaveKey}
              disabled={!apiKeyInput || saveStatus === 'saving'}
            >
              {saveStatus === 'saving' ? 'Saving...' :
               saveStatus === 'saved'  ? '✓ Saved'    : 'Save Key'}
            </button>
          </div>
        )}
      </div>

      <div className="settings-section">
        <h3>Storage Location</h3>
        <div className="settings-info-card">
          <div className="info-row">
            <span>API Key</span>
            <code>OS Credential Manager (keytar)</code>
          </div>
          <div className="info-row">
            <span>Scan Cache</span>
            <code>%APPDATA%/PhantomScope/phantomscope.db</code>
          </div>
          <div className="info-row">
            <span>Reports</span>
            <code>User-selected location</code>
          </div>
        </div>
      </div>

      <div className="settings-section">
        <h3>Platform Info</h3>
        <div className="settings-info-card">
          <div className="info-row">
            <span>Platform</span>
            <code>{(window as any).phantomAPI?.platform || 'browser'}</code>
          </div>
          <div className="info-row">
            <span>Version</span>
            <code>PhantomScope v1.0.0</code>
          </div>
          <div className="info-row">
            <span>ASM Core</span>
            <code>NASM x86-64 (SSE4.1)</code>
          </div>
        </div>
      </div>

      <div className="settings-section">
        <h3>Ethical Use Notice</h3>
        <div className="ethics-notice">
          PhantomScope is designed exclusively for authorized security research,
          incident response, and malware analysis on systems you own or have
          explicit written permission to scan. Unauthorized use is prohibited.
        </div>
      </div>
    </div>
  );
};
