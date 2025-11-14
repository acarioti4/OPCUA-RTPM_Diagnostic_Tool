// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  runOpcuaProbe: (params) =>
    ipcRenderer.invoke('diagnostics:opcua-probe', params),

  openExternal: (url) =>
    ipcRenderer.invoke('app:open-external', url),

  onShowAbout: (callback) => {
    ipcRenderer.on('show-about', (_event, data) => callback(data || {}));
  },
  onShowKeybinds: (callback) => {
    ipcRenderer.on('show-keybinds', (_event, data) => callback(data || {}));
  },

  onProbeProgress: (callback) => {
    ipcRenderer.on('diagnostics:progress', (_event, data) => callback(data || {}));
  },

  onSettingsSet: (callback) => {
    ipcRenderer.on('settings:set', (_event, data) => callback(data || {}));
  },

  settingsReady: (settings) => {
    ipcRenderer.send('settings:ready', settings || {});
  },

  onThemeSet: (callback) => {
    ipcRenderer.on('theme:set', (_event, data) => callback(data || {}));
  },

  themeReady: (payload) => {
    ipcRenderer.send('theme:ready', payload || {});
  }
});