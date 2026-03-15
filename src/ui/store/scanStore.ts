// ============================================================================
// PhantomScope — store/scanStore.ts
// Global State Management via Zustand
// ============================================================================

import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';

// ---- Types ----
export type ThreatLevel = 'clean' | 'informational' | 'suspicious' | 'critical';

export interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  isHidden: boolean;
  fromKernel: boolean;
  fromUsermode: boolean;
  entropy?: number;
  md5?: string;
  vtDetections?: number;
  threatName?: string;
  score: number;
  threatLevel: ThreatLevel;
}

export interface ScannedFile {
  path: string;
  md5: string;
  entropy: number;
  entropyClass: 0 | 1 | 2;
  fileSize: number;
  isSigned: boolean;
  vtDetections: number;
  threatName?: string;
  score: number;
  threatLevel: ThreatLevel;
  importedDlls?: string[];
  sections?: Array<{
    name: string;
    entropy: number;
    virtualSize: number;
    isExecutable: boolean;
  }>;
}

export interface GraphElement {
  data: {
    id: string;
    type: string;
    name: string;
    path?: string;
    md5?: string;
    pid?: number;
    ppid?: number;
    entropy?: number;
    vtDetections?: number;
    isSigned?: boolean;
    isHidden?: boolean;
    score: number;
    threatLevel: ThreatLevel;
    color: string;
    threatName?: string;
    source?: string;
    target?: string;
    label?: string;
  };
}

export interface ScanStats {
  totalNodes: number;
  totalEdges: number;
  hiddenProcesses: number;
  criticalCount: number;
  suspiciousCount: number;
}

export interface ScanProgress {
  phase: 'idle' | 'processes' | 'files' | 'virustotal' | 'graph' | 'complete' | 'error';
  message: string;
  filesScanned?: number;
  vtCompleted?: number;
  vtTotal?: number;
}

export type ActiveView = 'graph' | 'dashboard' | 'inspector' | 'settings' | 'history';

interface SelectedNode {
  id: string;
  data: GraphElement['data'];
}

interface ScanState {
  // Scan status
  isScanning: boolean;
  scanProgress: ScanProgress;
  lastScanTime: number | null;
  scanId: string | null;

  // Results
  processResult: {
    allProcesses: ProcessInfo[];
    hiddenProcesses: ProcessInfo[];
    hiddenCount: number;
    kernelCount: number;
    usermodeCount: number;
  } | null;
  fileResult: {
    files: ScannedFile[];
    highEntropyCount: number;
    vtDetectedCount: number;
    unsignedCount: number;
  } | null;
  graphData: {
    elements: { nodes: GraphElement[]; edges: GraphElement[] };
    stats: ScanStats;
  } | null;

  // UI state
  activeView: ActiveView;
  selectedNode: SelectedNode | null;
  searchQuery: string;
  filterLevel: ThreatLevel | 'all';
  graphLayoutName: string;

  // Settings
  hasApiKey: boolean;
  isPremiumVT: boolean;

  // Actions
  startScan: (options?: Record<string, unknown>) => Promise<void>;
  stopScan: () => void;
  setActiveView: (view: ActiveView) => void;
  selectNode: (node: SelectedNode | null) => void;
  setSearchQuery: (query: string) => void;
  setFilterLevel: (level: ThreatLevel | 'all') => void;
  setGraphLayout: (layout: string) => void;
  setHasApiKey: (has: boolean) => void;
  setScanProgress: (progress: Partial<ScanProgress>) => void;
  loadDemoData: () => void;
}

// ---- Demo data ----
const DEMO_GRAPH_DATA = {
  elements: {
    nodes: [
      { data: { id: 'proc-4', type: 'PHProcess', name: 'System', path: '', pid: 4, ppid: 0, entropy: 0, vtDetections: -1, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
      { data: { id: 'proc-644', type: 'PHProcess', name: 'smss.exe', path: 'C:\\Windows\\System32\\smss.exe', pid: 644, ppid: 4, entropy: 5.2, vtDetections: 0, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
      { data: { id: 'proc-1337', type: 'PHHiddenProcess', name: 'rootkit.sys', path: 'C:\\Windows\\System32\\drivers\\rootkit.sys', pid: 1337, ppid: 644, entropy: 7.8, vtDetections: 42, isSigned: false, isHidden: true, score: 95, threatLevel: 'critical' as ThreatLevel, color: '#FF2D55', threatName: 'Rootkit.Win32.TDSS' } },
      { data: { id: 'proc-4096', type: 'PHProcess', name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', pid: 4096, ppid: 644, entropy: 6.1, vtDetections: 0, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
      { data: { id: 'proc-5120', type: 'PHProcess', name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', pid: 5120, ppid: 4096, entropy: 5.9, vtDetections: 0, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
      { data: { id: 'file-suspicious', type: 'PHFile', name: 'suspicious.exe', path: 'C:\\Temp\\suspicious.exe', md5: '112233445566778899aabbccddeeff00', entropy: 7.1, vtDetections: 0, isSigned: false, isHidden: false, score: 45, threatLevel: 'suspicious' as ThreatLevel, color: '#FF9F0A' } },
      { data: { id: 'file-calc', type: 'PHFile', name: 'calc.exe', path: 'C:\\Windows\\System32\\calc.exe', md5: 'd41d8cd98f00b204e9800998ecf8427e', entropy: 5.8, vtDetections: 0, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
      { data: { id: 'svc-defender', type: 'PHService', name: 'WinDefend', path: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.0.0\\MsMpEng.exe', entropy: 5.5, vtDetections: 0, isSigned: true, isHidden: false, score: 0, threatLevel: 'clean' as ThreatLevel, color: '#30D158' } },
    ],
    edges: [
      { data: { id: 'e1', source: 'proc-4', target: 'proc-644', type: 'PHSpawnsProcess', label: 'spawns' } },
      { data: { id: 'e2', source: 'proc-644', target: 'proc-1337', type: 'PHSpawnsProcess', label: 'spawns' } },
      { data: { id: 'e3', source: 'proc-644', target: 'proc-4096', type: 'PHSpawnsProcess', label: 'spawns' } },
      { data: { id: 'e4', source: 'proc-4096', target: 'proc-5120', type: 'PHSpawnsProcess', label: 'spawns' } },
      { data: { id: 'e5', source: 'proc-1337', target: 'file-suspicious', type: 'PHLoadsModule', label: 'loads' } },
      { data: { id: 'e6', source: 'proc-4096', target: 'file-calc', type: 'PHImports', label: 'imports' } },
      { data: { id: 'e7', source: 'proc-4', target: 'svc-defender', type: 'PHRunsAs', label: 'runs' } },
    ],
  },
  stats: { totalNodes: 8, totalEdges: 7, hiddenProcesses: 1, criticalCount: 1, suspiciousCount: 1 },
};

// ---- Store ----
export const useScanStore = create<ScanState>()(
  immer((set, get) => ({
    isScanning: false,
    scanProgress: { phase: 'idle', message: '' },
    lastScanTime: null,
    scanId: null,
    processResult: null,
    fileResult: null,
    graphData: null,
    activeView: 'graph',
    selectedNode: null,
    searchQuery: '',
    filterLevel: 'all',
    graphLayoutName: 'cose-bilkent',
    hasApiKey: false,
    isPremiumVT: false,

    startScan: async (options = {}) => {
      set(state => {
        state.isScanning = true;
        state.scanProgress = { phase: 'processes', message: 'Initializing scan...' };
        state.graphData = null;
      });

      const api = (window as any).phantomAPI;
      if (!api) {
        // Load demo data in browser preview
        get().loadDemoData();
        return;
      }

      // Register progress listener
      const removeListener = api.on('scan:progress', (progress: any) => {
        set(state => {
          state.scanProgress = {
            phase: progress.phase,
            message: progress.message,
            filesScanned: progress.filesScanned,
            vtCompleted: progress.vtCompleted,
            vtTotal: progress.vtTotal,
          };
          if (progress.data) {
            if (progress.phase === 'processes') state.processResult = progress.data;
            if (progress.phase === 'files') state.fileResult = progress.data;
          }
        });
      });

      const removeComplete = api.on('scan:complete', (result: any) => {
        set(state => {
          state.isScanning = false;
          state.scanProgress = { phase: 'complete', message: 'Scan complete' };
          state.processResult = result.processResult;
          state.fileResult = result.fileResult;
          state.graphData = result.graphData;
          state.lastScanTime = Date.now();
        });
        removeListener();
        removeComplete();
      });

      try {
        await api.startScan(options);
      } catch (err) {
        set(state => {
          state.isScanning = false;
          state.scanProgress = { phase: 'error', message: String(err) };
        });
        removeListener();
        removeComplete();
      }
    },

    stopScan: () => {
      set(state => {
        state.isScanning = false;
        state.scanProgress = { phase: 'idle', message: 'Scan stopped' };
      });
    },

    setActiveView: (view) => set(state => { state.activeView = view; }),
    selectNode: (node) => set(state => { state.selectedNode = node; }),
    setSearchQuery: (q) => set(state => { state.searchQuery = q; }),
    setFilterLevel: (level) => set(state => { state.filterLevel = level; }),
    setGraphLayout: (layout) => set(state => { state.graphLayoutName = layout; }),
    setHasApiKey: (has) => set(state => { state.hasApiKey = has; }),

    setScanProgress: (progress) => set(state => {
      Object.assign(state.scanProgress, progress);
    }),

    loadDemoData: () => {
      set(state => {
        state.isScanning = false;
        state.graphData = DEMO_GRAPH_DATA;
        state.scanProgress = { phase: 'complete', message: 'Demo scan complete' };
        state.lastScanTime = Date.now();
        state.processResult = {
          allProcesses: [],
          hiddenProcesses: [{ pid: 1337, ppid: 644, name: 'rootkit.sys', path: '', isHidden: true, fromKernel: true, fromUsermode: false, score: 95, threatLevel: 'critical' }],
          hiddenCount: 1,
          kernelCount: 6,
          usermodeCount: 5,
        };
        state.fileResult = {
          files: [],
          highEntropyCount: 2,
          vtDetectedCount: 1,
          unsignedCount: 2,
        };
      });
    },
  }))
);
