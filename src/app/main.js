// ============================================================================
// PhantomScope — main.js
// Electron Main Process
//
// Responsibilities:
//   - Create and manage the application window
//   - Load the native C++ addon (phantomscope.node)
//   - Handle privileged IPC messages from the renderer
//   - Manage scan pipeline orchestration
//   - Secure API key storage via keytar
//   - PDF report generation
//
// Security: contextIsolation=true, nodeIntegration=false, preload script
// handles the IPC bridge to prevent renderer XSS escalation.
// ============================================================================

'use strict';

const { app, BrowserWindow, ipcMain, shell, dialog, Menu } = require('electron');
const path = require('path');
const fs   = require('fs');
const os   = require('os');

// ---- Conditional native addon loading ----
let nativeAddon = null;
try {
  nativeAddon = require('./build/Release/phantomscope.node');
  console.log('[PhantomScope] Native addon loaded successfully');
} catch (err) {
  console.warn('[PhantomScope] Native addon not found — running in demo mode:', err.message);
  nativeAddon = createDemoAddon();
}

// ---- Keytar for secure API key storage ----
let keytar;
try {
  keytar = require('keytar');
} catch (err) {
  console.warn('[PhantomScope] keytar not available — API key will use fallback storage');
  keytar = createFallbackKeytar();
}

// ---- SQLite cache ----
let db;
try {
  const Database = require('better-sqlite3');
  const dbPath   = path.join(app.getPath('userData'), 'phantomscope.db');
  db = new Database(dbPath);
  initializeDatabase(db);
  console.log('[PhantomScope] SQLite cache initialized:', dbPath);
} catch (err) {
  console.warn('[PhantomScope] SQLite not available:', err.message);
}

// ============================================================================
// Database initialization
// ============================================================================
function initializeDatabase(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      path         TEXT PRIMARY KEY,
      md5          TEXT,
      sha256       TEXT,
      entropy      REAL,
      entropy_class INTEGER,
      file_size    INTEGER,
      vt_detections INTEGER DEFAULT -1,
      vt_result_json TEXT,
      vt_scan_time INTEGER,
      threat_name  TEXT,
      scan_time    INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    CREATE TABLE IF NOT EXISTS scans (
      scan_id      TEXT PRIMARY KEY,
      start_time   INTEGER NOT NULL,
      end_time     INTEGER,
      root_path    TEXT,
      summary_json TEXT,
      status       TEXT DEFAULT 'running'
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_files_md5       ON files(md5);
    CREATE INDEX IF NOT EXISTS idx_files_entropy   ON files(entropy);
    CREATE INDEX IF NOT EXISTS idx_files_vt_det    ON files(vt_detections);
  `);
}

// ============================================================================
// Window creation
// ============================================================================
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width:  1440,
    height: 900,
    minWidth:  1100,
    minHeight: 700,
    backgroundColor: '#0A0A0F',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
    frame: false,
    webPreferences: {
      preload:               path.join(__dirname, 'preload.js'),
      contextIsolation:      true,   // SECURITY: isolate renderer context
      nodeIntegration:       false,  // SECURITY: no Node.js in renderer
      webSecurity:           true,
      allowRunningInsecureContent: false,
      sandbox:               false,  // needed for native addon IPC
    },
    icon: path.join(__dirname, 'resources', 'icon.png'),
    show: false,  // show after 'ready-to-show' to avoid flash
  });

  // Load the React app
  const isDev = process.env.NODE_ENV === 'development';
  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Security: open external links in system browser, not Electron
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  // Block navigation away from the app
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const appUrl = isDev ? 'http://localhost:3000' : 'file://';
    if (!url.startsWith(appUrl)) {
      event.preventDefault();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  createWindow();
  setupApplicationMenu();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ============================================================================
// IPC Handlers — Main Process
// All messages validated before processing (defense against renderer XSS)
// ============================================================================

// ---- Window controls ----
ipcMain.handle('window:minimize', () => mainWindow?.minimize());
ipcMain.handle('window:maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.handle('window:close', () => mainWindow?.close());

// ---- Scan pipeline ----
ipcMain.handle('scan:start', async (event, options) => {
  // Validate options schema
  if (!options || typeof options !== 'object') {
    return { success: false, error: 'Invalid scan options' };
  }

  const scanId = generateScanId();

  try {
    // Record scan start
    if (db) {
      db.prepare(`INSERT INTO scans (scan_id, start_time, root_path) VALUES (?, ?, ?)`)
        .run(scanId, Date.now(), options.rootPath || 'system');
    }

    // Phase 1: Process enumeration
    mainWindow?.webContents.send('scan:progress', {
      phase: 'processes',
      message: 'Enumerating processes via direct syscall...',
      scanId
    });

    let processResult;
    if (nativeAddon && nativeAddon.runProcessDiff) {
      processResult = nativeAddon.runProcessDiff();
    } else {
      processResult = await getDemoProcessResult();
    }

    mainWindow?.webContents.send('scan:progress', {
      phase: 'processes',
      message: `Found ${processResult.allProcesses.length} processes (${processResult.hiddenCount} hidden)`,
      data: processResult,
      scanId
    });

    // Phase 2: File system scan
    if (options.scanFiles !== false) {
      mainWindow?.webContents.send('scan:progress', {
        phase: 'files',
        message: 'Scanning filesystem for executables...',
        scanId
      });

      const scanRoot = options.rootPath || (
        process.platform === 'win32' ? 'C:\\Windows\\System32' : '/usr/bin'
      );

      let fileResult;
      if (nativeAddon && nativeAddon.scanPath) {
        fileResult = nativeAddon.scanPath({
          rootPath: scanRoot,
          maxFiles: options.maxFiles || 500,
          scanSystemDirs: options.scanSystemDirs || false,
        });
      } else {
        fileResult = await getDemoFileResult();
      }

      mainWindow?.webContents.send('scan:progress', {
        phase: 'files',
        message: `Scanned ${fileResult.files.length} files`,
        data: fileResult,
        scanId
      });

      // Phase 3: VirusTotal lookups (if API key available)
      if (options.runVirusTotal !== false) {
        mainWindow?.webContents.send('scan:progress', {
          phase: 'virustotal',
          message: 'Submitting hashes to VirusTotal...',
          scanId
        });

        const apiKey = await getApiKey();
        if (apiKey) {
          const vtResults = await runVTLookups(fileResult.files, apiKey, (progress) => {
            mainWindow?.webContents.send('scan:progress', {
              phase: 'virustotal',
              message: `VirusTotal: ${progress.completed}/${progress.total}`,
              progress,
              scanId
            });
          });

          // Update file results with VT data
          fileResult.vtResults = vtResults;
        }
      }

      // Phase 4: Build graph
      mainWindow?.webContents.send('scan:progress', {
        phase: 'graph',
        message: 'Building process relationship graph...',
        scanId
      });

      let graphData;
      if (nativeAddon && nativeAddon.buildGraph) {
        graphData = nativeAddon.buildGraph(
          processResult,
          fileResult,
          fileResult.vtResults || []
        );
      } else {
        graphData = buildDemoGraph(processResult, fileResult);
      }

      // Cache results
      if (db && fileResult.files) {
        cacheFileResults(db, fileResult.files);
      }

      // Complete
      const endTime = Date.now();
      if (db) {
        db.prepare(`UPDATE scans SET end_time=?, status='completed', summary_json=? WHERE scan_id=?`)
          .run(endTime, JSON.stringify(graphData.stats), scanId);
      }

      mainWindow?.webContents.send('scan:complete', {
        scanId,
        processResult,
        fileResult,
        graphData,
        duration: endTime - Date.now(),
      });

      return { success: true, scanId, graphData };
    }
  } catch (err) {
    console.error('[PhantomScope] Scan error:', err);
    if (db) {
      db.prepare(`UPDATE scans SET status='error' WHERE scan_id=?`).run(scanId);
    }
    return { success: false, error: err.message };
  }
});

// ---- File operations ----
ipcMain.handle('file:open', async (event, filePath) => {
  if (typeof filePath !== 'string') return { success: false };
  const dir = path.dirname(filePath);
  try {
    await shell.openPath(dir);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('file:scan-single', async (event, filePath) => {
  if (typeof filePath !== 'string') return null;
  if (!nativeAddon?.scanSingleFile) return getDemoSingleFile(filePath);
  return nativeAddon.scanSingleFile(filePath);
});

// ---- VT operations ----
ipcMain.handle('vt:lookup', async (event, md5) => {
  if (typeof md5 !== 'string' || !/^[a-f0-9]{32}$/i.test(md5)) {
    return { error: 'Invalid MD5 hash' };
  }

  // Check cache
  if (db) {
    const cached = db.prepare(`SELECT vt_result_json, vt_scan_time FROM files WHERE md5=?`)
      .get(md5);
    if (cached?.vt_result_json) {
      const cacheAge = Date.now() - (cached.vt_scan_time || 0);
      if (cacheAge < 86400000) {  // 24 hour TTL
        return { ...JSON.parse(cached.vt_result_json), fromCache: true };
      }
    }
  }

  const apiKey = await getApiKey();
  if (!apiKey) return { error: 'No API key configured' };

  if (!nativeAddon?.vtLookup) return { error: 'Native addon not available' };
  const result = nativeAddon.vtLookup(md5, apiKey);

  // Cache result
  if (db && result && !result.error) {
    db.prepare(`UPDATE files SET vt_result_json=?, vt_scan_time=?, vt_detections=? WHERE md5=?`)
      .run(JSON.stringify(result), Date.now(), result.detections || 0, md5);
  }

  return result;
});

// ---- API key management (keytar) ----
ipcMain.handle('settings:set-api-key', async (event, key) => {
  if (typeof key !== 'string') return { success: false };
  try {
    await keytar.setPassword('PhantomScope', 'vt_api_key', key);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('settings:has-api-key', async () => {
  const key = await getApiKey();
  return { hasKey: !!key };
});

ipcMain.handle('settings:clear-api-key', async () => {
  try {
    await keytar.deletePassword('PhantomScope', 'vt_api_key');
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ---- Scan history ----
ipcMain.handle('history:get', () => {
  if (!db) return [];
  return db.prepare(`
    SELECT scan_id, start_time, end_time, root_path, summary_json, status
    FROM scans ORDER BY start_time DESC LIMIT 50
  `).all();
});

// ---- Report export ----
ipcMain.handle('report:export-pdf', async (event, scanData) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Forensic Report',
    defaultPath: `PhantomScope_Report_${new Date().toISOString().slice(0, 10)}.pdf`,
    filters: [{ name: 'PDF', extensions: ['pdf'] }],
  });

  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    const pdfmake = require('pdfmake/build/pdfmake');
    const vfs     = require('pdfmake/build/vfs_fonts');
    pdfmake.vfs   = vfs.pdfMake.vfs;

    const docDef  = generateReportDefinition(scanData);
    const pdfDoc  = pdfmake.createPdf(docDef);

    await new Promise((resolve, reject) => {
      pdfDoc.getBuffer((buffer) => {
        fs.writeFile(filePath, buffer, (err) => {
          if (err) reject(err); else resolve();
        });
      });
    });

    return { success: true, path: filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('report:export-json', async (event, scanData) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Export JSON Report',
    defaultPath: `PhantomScope_${new Date().toISOString().slice(0, 10)}.json`,
    filters: [{ name: 'JSON', extensions: ['json'] }],
  });

  if (canceled || !filePath) return { success: false, canceled: true };

  fs.writeFileSync(filePath, JSON.stringify(scanData, null, 2));
  return { success: true, path: filePath };
});

// ============================================================================
// Helper functions
// ============================================================================

async function getApiKey() {
  try {
    return await keytar.getPassword('PhantomScope', 'vt_api_key');
  } catch {
    return null;
  }
}

async function runVTLookups(files, apiKey, onProgress) {
  const results = [];
  const delay = ms => new Promise(r => setTimeout(r, ms));

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    if (!file.md5) continue;

    onProgress({ completed: i, total: files.length, currentFile: file.path });

    if (nativeAddon?.vtLookup) {
      const result = nativeAddon.vtLookup(file.md5, apiKey);
      results.push(result);
    }

    // Rate limiting: 4 req/min = 1 req per 15s on free tier
    await delay(15000);
  }

  return results;
}

function cacheFileResults(db, files) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO files
    (path, md5, entropy, entropy_class, file_size, vt_detections, threat_name, scan_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
  `);

  const insertMany = db.transaction((files) => {
    for (const f of files) {
      stmt.run(
        f.path, f.md5 || null,
        f.entropy || 0, f.entropyClass || 0,
        f.fileSize || 0, f.vtDetections || -1,
        f.threatName || null
      );
    }
  });

  insertMany(files);
}

function generateScanId() {
  return 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function setupApplicationMenu() {
  const template = [
    {
      label: 'PhantomScope',
      submenu: [
        { label: 'About PhantomScope', role: 'about' },
        { type: 'separator' },
        { label: 'Quit', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() }
      ]
    },
    {
      label: 'Scan',
      submenu: [
        { label: 'New Scan', accelerator: 'CmdOrCtrl+N',
          click: () => mainWindow?.webContents.send('menu:new-scan') },
        { label: 'Stop Scan', accelerator: 'CmdOrCtrl+.',
          click: () => mainWindow?.webContents.send('menu:stop-scan') },
      ]
    },
    {
      label: 'View',
      submenu: [
        { label: 'Graph View', accelerator: 'CmdOrCtrl+1',
          click: () => mainWindow?.webContents.send('menu:view-graph') },
        { label: 'Dashboard', accelerator: 'CmdOrCtrl+2',
          click: () => mainWindow?.webContents.send('menu:view-dashboard') },
        { type: 'separator' },
        { role: 'reload' },
        { role: 'toggleDevTools' },
      ]
    }
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ============================================================================
// PDF report definition
// ============================================================================
function generateReportDefinition(scanData) {
  const { graphData, processResult, fileResult, scanTime } = scanData;
  const hiddenProcs = processResult?.hiddenProcesses || [];
  const criticalFiles = (fileResult?.files || [])
    .filter(f => f.vtDetections > 0 || f.entropy > 6.5)
    .slice(0, 50);

  return {
    pageSize: 'A4',
    pageMargins: [40, 60, 40, 60],
    header: (currentPage) => ({
      text: `PhantomScope Forensic Report — Page ${currentPage}`,
      alignment: 'right', fontSize: 9, color: '#888', margin: [0, 20, 40, 0]
    }),
    content: [
      { text: 'PhantomScope', style: 'title' },
      { text: 'Rootkit Detection & Forensic Analysis Report', style: 'subtitle' },
      { text: `Generated: ${new Date().toISOString()}`, style: 'meta' },
      { text: '\n' },

      { text: 'Executive Summary', style: 'h2' },
      {
        table: {
          widths: ['*', '*', '*', '*'],
          body: [[
            { text: `${hiddenProcs.length}\nHidden Processes`, style: 'statCard', fillColor: hiddenProcs.length > 0 ? '#FF2D55' : '#1C1C1E' },
            { text: `${graphData?.stats?.criticalCount || 0}\nCritical Threats`, style: 'statCard', fillColor: '#FF2D55' },
            { text: `${fileResult?.vtDetectedCount || 0}\nVT Detections`, style: 'statCard' },
            { text: `${fileResult?.highEntropyCount || 0}\nHigh Entropy`, style: 'statCard' },
          ]]
        }
      },

      { text: '\n' },
      { text: 'Hidden Processes', style: 'h2' },
      hiddenProcs.length > 0
        ? {
          table: {
            headerRows: 1,
            widths: ['auto', '*', '*'],
            body: [
              [{ text: 'PID', bold: true }, { text: 'Name', bold: true }, { text: 'Detection Method', bold: true }],
              ...hiddenProcs.map(p => [
                { text: p.pid.toString(), color: '#FF2D55' },
                p.name,
                'Kernel/UserMode PID Delta'
              ])
            ]
          }
        }
        : { text: 'No hidden processes detected.', italics: true, color: '#30D158' },

      { text: '\n' },
      { text: 'Critical & Suspicious Files', style: 'h2' },
      criticalFiles.length > 0
        ? {
          table: {
            headerRows: 1,
            widths: ['*', 'auto', 'auto', 'auto'],
            body: [
              [{ text: 'Path', bold: true }, { text: 'Entropy', bold: true },
               { text: 'VT Hits', bold: true }, { text: 'MD5', bold: true }],
              ...criticalFiles.map(f => [
                { text: f.path, fontSize: 8 },
                { text: f.entropy?.toFixed(2) || 'N/A',
                  color: f.entropy > 6.5 ? '#FF9F0A' : '#EBEBF5' },
                { text: f.vtDetections >= 0 ? f.vtDetections.toString() : 'N/A',
                  color: f.vtDetections > 0 ? '#FF2D55' : '#30D158' },
                { text: f.md5 || 'N/A', fontSize: 7 }
              ])
            ]
          }
        }
        : { text: 'No critical files found.', italics: true, color: '#30D158' },

      { text: '\n\nPhantomScope v1.0 — Authorized Security Research Use Only', style: 'footer' }
    ],
    styles: {
      title:    { fontSize: 28, bold: true, color: '#0A84FF', marginBottom: 4 },
      subtitle: { fontSize: 14, color: '#EBEBF5', marginBottom: 8 },
      meta:     { fontSize: 10, color: '#8E8E93' },
      h2:       { fontSize: 16, bold: true, color: '#EBEBF5', marginTop: 16, marginBottom: 8 },
      statCard: { fontSize: 18, bold: true, color: '#EBEBF5', alignment: 'center',
                  margin: [8, 8, 8, 8] },
      footer:   { fontSize: 9, color: '#636366', alignment: 'center' },
    }
  };
}

// ============================================================================
// Demo mode data (used when native addon not available)
// ============================================================================
function createDemoAddon() {
  return {
    runProcessDiff: null,
    scanPath: null,
    vtLookup: null,
    buildGraph: null,
    scanSingleFile: null,
  };
}

function createFallbackKeytar() {
  let stored_key = null;
  return {
    getPassword: async () => stored_key,
    setPassword: async (_, __, key) => { stored_key = key; },
    deletePassword: async () => { stored_key = null; },
  };
}

async function getDemoProcessResult() {
  return {
    allProcesses: [
      { pid: 4,    ppid: 0,    name: 'System',     path: '', isHidden: false, fromKernel: true, fromUsermode: true, score: 0 },
      { pid: 644,  ppid: 4,    name: 'smss.exe',   path: 'C:\\Windows\\System32\\smss.exe', isHidden: false, fromKernel: true, fromUsermode: true, score: 0 },
      { pid: 788,  ppid: 644,  name: 'csrss.exe',  path: 'C:\\Windows\\System32\\csrss.exe', isHidden: false, fromKernel: true, fromUsermode: true, score: 0 },
      { pid: 1337, ppid: 644,  name: 'rootkit.sys',path: 'C:\\Windows\\System32\\drivers\\rootkit.sys', isHidden: true, fromKernel: true, fromUsermode: false, score: 85 },
      { pid: 4096, ppid: 788,  name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', isHidden: false, fromKernel: true, fromUsermode: true, score: 0 },
      { pid: 5120, ppid: 4096, name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', isHidden: false, fromKernel: true, fromUsermode: true, score: 5 },
    ],
    hiddenProcesses: [
      { pid: 1337, ppid: 644, name: 'rootkit.sys', path: 'C:\\Windows\\System32\\drivers\\rootkit.sys', isHidden: true, score: 85 },
    ],
    hiddenCount: 1,
    kernelCount: 6,
    usermodeCount: 5,
  };
}

async function getDemoFileResult() {
  return {
    files: [
      { path: 'C:\\Windows\\System32\\calc.exe', md5: 'd41d8cd98f00b204e9800998ecf8427e', entropy: 6.2, entropyClass: 0, fileSize: 1234567, isSigned: true, vtDetections: 0, importedDlls: ['ntdll.dll', 'kernel32.dll'] },
      { path: 'C:\\Windows\\System32\\drivers\\rootkit.sys', md5: 'aabbccddeeff00112233445566778899', entropy: 7.8, entropyClass: 2, fileSize: 45678, isSigned: false, vtDetections: 42, threatName: 'Trojan.Rootkit.A', importedDlls: ['ntoskrnl.exe', 'hal.dll'] },
      { path: 'C:\\Temp\\suspicious.exe', md5: '112233445566778899aabbccddeeff00', entropy: 7.1, entropyClass: 1, fileSize: 98765, isSigned: false, vtDetections: 0, importedDlls: ['kernel32.dll', 'ws2_32.dll'] },
    ],
    highEntropyCount: 2,
    vtDetectedCount: 1,
    unsignedCount: 2,
  };
}

function getDemoSingleFile(filePath) {
  return {
    path: filePath,
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    entropy: 5.8,
    entropyClass: 0,
    fileSize: 102400,
    isSigned: false,
    vtDetections: -1,
    importedDlls: [],
  };
}

function buildDemoGraph(processResult, fileResult) {
  const nodes = [];
  const edges = [];

  for (const proc of processResult.allProcesses || []) {
    nodes.push({
      data: {
        id: `proc-${proc.pid}`,
        type: proc.isHidden ? 'PHHiddenProcess' : 'PHProcess',
        name: proc.name,
        path: proc.path,
        pid: proc.pid,
        ppid: proc.ppid,
        entropy: proc.entropy || 0,
        vtDetections: proc.vtDetections || -1,
        isSigned: proc.isSigned !== false,
        isHidden: proc.isHidden || false,
        score: proc.score || 0,
        threatLevel: proc.isHidden ? 'critical' : 'clean',
        color: proc.isHidden ? '#FF2D55' : '#30D158',
      }
    });

    if (proc.ppid && proc.ppid !== proc.pid) {
      edges.push({
        data: {
          id: `edge-${proc.ppid}-${proc.pid}`,
          source: `proc-${proc.ppid}`,
          target: `proc-${proc.pid}`,
          type: 'PHSpawnsProcess',
          label: 'spawns',
        }
      });
    }
  }

  for (const file of fileResult.files || []) {
    nodes.push({
      data: {
        id: `file-${file.path.replace(/[^a-zA-Z0-9]/g, '_')}`,
        type: 'PHFile',
        name: path.basename(file.path),
        path: file.path,
        md5: file.md5,
        entropy: file.entropy || 0,
        vtDetections: file.vtDetections || -1,
        isSigned: file.isSigned || false,
        score: file.vtDetections > 0 ? 80 : file.entropy > 6.5 ? 40 : 0,
        threatLevel: file.vtDetections > 0 ? 'critical' : file.entropy > 6.5 ? 'suspicious' : 'clean',
        color: file.vtDetections > 0 ? '#FF2D55' : file.entropy > 6.5 ? '#FF9F0A' : '#30D158',
        threatName: file.threatName || '',
      }
    });
  }

  return {
    elements: { nodes, edges },
    stats: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      hiddenProcesses: processResult.hiddenCount || 0,
      criticalCount: nodes.filter(n => n.data.threatLevel === 'critical').length,
      suspiciousCount: nodes.filter(n => n.data.threatLevel === 'suspicious').length,
    }
  };
}
