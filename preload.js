// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  testPorts: (host, startPort, endPort, concurrency) => 
    ipcRenderer.invoke('test-ports', { host, startPort, endPort, concurrency }),

  onTestProgress: (callback) => {
    ipcRenderer.on('test-progress', (event, data) => callback(data));
  },

  detectService: (serverPort) =>
    ipcRenderer.invoke('detect-service', { serverPort }),

  opcHelloTest: (host, port, endpointUrl) =>
    ipcRenderer.invoke('opc-hello-test', { host, port, endpointUrl }),

  listListeners: (filterPorts) =>
    ipcRenderer.invoke('list-listeners', { filterPorts }),

  listAdapters: () =>
    ipcRenderer.invoke('list-adapters'),

  checkFirewall: (port) =>
    ipcRenderer.invoke('check-firewall', { port }),

  addFirewallRule: (port, name) =>
    ipcRenderer.invoke('add-firewall-rule', { port, name }),

  onShowAbout: (callback) => {
    ipcRenderer.on('show-about', (_event, data) => callback(data || {}));
  }
});