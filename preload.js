// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  runOpcuaProbe: (params) =>
    ipcRenderer.invoke('diagnostics:opcua-probe', params),

  onShowAbout: (callback) => {
    ipcRenderer.on('show-about', (_event, data) => callback(data || {}));
  }
});