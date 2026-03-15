// ============================================================================
// PhantomScope — preload.js
// Electron Preload Script — Secure IPC Bridge
//
// Exposes a typed, validated API surface to the renderer process via
// contextBridge. The renderer has ZERO direct access to Node.js or
// Electron APIs — all communication goes through this controlled bridge.
//
// Security model: Every exposed function validates its arguments before
// forwarding to ipcMain. This prevents renderer-side XSS from escalating
// to arbitrary main-process code execution.
// ============================================================================

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// ============================================================================
// Allowed IPC channels (whitelist)
// ============================================================================
const VALID_SEND_CHANNELS = [
  'scan:start', 'scan:stop',
  'file:open', 'file:scan-single',
  'vt:lookup',
  'settings:set-api-key', 'settings:has-api-key', 'settings:clear-api-key',
  'history:get',
  'report:export-pdf', 'report:export-json',
  'window:minimize', 'window:maximize', 'window:close',
];

const VALID_RECEIVE_CHANNELS = [
  'scan:progress', 'scan:complete', 'scan:error',
  'menu:new-scan', 'menu:stop-scan', 'menu:view-graph', 'menu:view-dashboard',
];

// ============================================================================
// Type validators
// ============================================================================
const isString    = (v) => typeof v === 'string';
const isObject    = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isMD5       = (v) => isString(v) && /^[a-f0-9]{32}$/i.test(v);
const isApiKey    = (v) => isString(v) && v.length > 8 && v.length < 256;

// ============================================================================
// Expose validated API to renderer
// ============================================================================
contextBridge.exposeInMainWorld('phantomAPI', {

  // ---- Scan operations ----
  startScan: (options) => {
    if (!isObject(options)) throw new Error('startScan: options must be an object');
    return ipcRenderer.invoke('scan:start', {
      rootPath:       isString(options.rootPath)    ? options.rootPath    : null,
      maxFiles:       Number.isInteger(options.maxFiles) ? options.maxFiles : 500,
      scanFiles:      options.scanFiles    !== false,
      runVirusTotal:  options.runVirusTotal !== false,
      scanSystemDirs: options.scanSystemDirs === true,
    });
  },

  // ---- File operations ----
  openFileInExplorer: (filePath) => {
    if (!isString(filePath)) throw new Error('openFileInExplorer: path must be string');
    return ipcRenderer.invoke('file:open', filePath);
  },

  scanSingleFile: (filePath) => {
    if (!isString(filePath)) throw new Error('scanSingleFile: path must be string');
    return ipcRenderer.invoke('file:scan-single', filePath);
  },

  // ---- VirusTotal operations ----
  vtLookup: (md5) => {
    if (!isMD5(md5)) throw new Error('vtLookup: invalid MD5 hash format');
    return ipcRenderer.invoke('vt:lookup', md5);
  },

  // ---- Settings ----
  setApiKey: (key) => {
    if (!isApiKey(key)) throw new Error('setApiKey: invalid API key format');
    return ipcRenderer.invoke('settings:set-api-key', key);
  },

  hasApiKey: () => ipcRenderer.invoke('settings:has-api-key'),

  clearApiKey: () => ipcRenderer.invoke('settings:clear-api-key'),

  // ---- Scan history ----
  getScanHistory: () => ipcRenderer.invoke('history:get'),

  // ---- Report export ----
  exportPDF: (scanData) => {
    if (!isObject(scanData)) throw new Error('exportPDF: invalid scan data');
    return ipcRenderer.invoke('report:export-pdf', scanData);
  },

  exportJSON: (scanData) => {
    if (!isObject(scanData)) throw new Error('exportJSON: invalid scan data');
    return ipcRenderer.invoke('report:export-json', scanData);
  },

  // ---- Window controls ----
  minimizeWindow: () => ipcRenderer.invoke('window:minimize'),
  maximizeWindow: () => ipcRenderer.invoke('window:maximize'),
  closeWindow:    () => ipcRenderer.invoke('window:close'),

  // ---- Event subscriptions ----
  on: (channel, callback) => {
    if (!VALID_RECEIVE_CHANNELS.includes(channel)) {
      throw new Error(`on: channel "${channel}" not allowed`);
    }
    if (typeof callback !== 'function') {
      throw new Error('on: callback must be a function');
    }

    // Wrap in a removal function to prevent memory leaks
    const listener = (_event, ...args) => callback(...args);
    ipcRenderer.on(channel, listener);

    return () => ipcRenderer.removeListener(channel, listener);
  },

  off: (channel, callback) => {
    if (!VALID_RECEIVE_CHANNELS.includes(channel)) return;
    ipcRenderer.removeListener(channel, callback);
  },

  removeAllListeners: (channel) => {
    if (VALID_RECEIVE_CHANNELS.includes(channel)) {
      ipcRenderer.removeAllListeners(channel);
    }
  },

  // ---- Platform info ----
  platform: process.platform,
  version: '1.0.0',
});
