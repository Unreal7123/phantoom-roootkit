// ============================================================================
// PhantomScope — App.tsx
// Root Application Component
// ============================================================================

import React, { useEffect, useCallback } from 'react';
import { useScanStore } from './store/scanStore';
import { TitleBar }      from './components/TitleBar';
import { SideNav }       from './components/SideNav';
import { GraphView }     from './components/GraphView';
import { Dashboard }     from './components/Dashboard';
import { FileInspector } from './components/FileInspector';
import { SettingsPanel } from './components/SettingsPanel';
import { ScanProgress }  from './components/ScanProgress';
import { ThreatPanel }   from './components/ThreatPanel';
import './styles/app.css';

const App: React.FC = () => {
  const { activeView, isScanning, loadDemoData, setHasApiKey } = useScanStore();

  useEffect(() => {
    // Check API key status on mount
    const api = (window as any).phantomAPI;
    if (api) {
      api.hasApiKey().then(({ hasKey }: { hasKey: boolean }) => {
        setHasApiKey(hasKey);
      });
    } else {
      // Running in browser (dev/preview) — load demo data
      setTimeout(loadDemoData, 800);
    }

    // Listen for menu events
    if (api) {
      const rm1 = api.on('menu:view-graph',     () => useScanStore.getState().setActiveView('graph'));
      const rm2 = api.on('menu:view-dashboard', () => useScanStore.getState().setActiveView('dashboard'));
      const rm3 = api.on('menu:new-scan',       () => useScanStore.getState().startScan());
      return () => { rm1?.(); rm2?.(); rm3?.(); };
    }
  }, []);

  const renderMainContent = () => {
    switch (activeView) {
      case 'graph':     return <GraphView />;
      case 'dashboard': return <Dashboard />;
      case 'inspector': return <FileInspector />;
      case 'settings':  return <SettingsPanel />;
      case 'history':   return <Dashboard showHistory />;
      default:          return <GraphView />;
    }
  };

  return (
    <div className="app-root">
      <TitleBar />
      <div className="app-body">
        <SideNav />
        <main className="app-main">
          {renderMainContent()}
        </main>
        {activeView === 'graph' && <ThreatPanel />}
      </div>
      {isScanning && <ScanProgress />}
    </div>
  );
};

export default App;
