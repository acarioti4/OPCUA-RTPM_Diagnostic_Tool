// main.js
const { app, BrowserWindow, ipcMain, Menu, shell } = require('electron');
const path = require('path');
const net = require('net');
const fs = require('fs');
const { exec } = require('child_process');
const os = require('os');
let opcua = null;
try {
  // Lazy require to avoid hard failure if not installed yet
  // eslint-disable-next-line global-require
  opcua = require('node-opcua');
} catch {
  opcua = null;
}
let CapLib = null;
try {
  // Optional dependency
  // eslint-disable-next-line global-require
  CapLib = require('cap');
} catch {
  CapLib = null;
}
const { ensureLogDir } = require('./logs');
const { parseListeningPorts } = require('./netstat');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    show: false,
    backgroundColor: '#0a0b0d',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      backgroundThrottling: false
    }
  });

  mainWindow.loadFile('index.html');
  
  // Optimized: show window immediately when ready
  mainWindow.once('ready-to-show', () => {
    if (!mainWindow.isDestroyed()) {
      mainWindow.show();
      // Focus window for better UX
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
  
  // Sync menu when window finishes loading - optimized delay
  mainWindow.webContents.once('did-finish-load', () => {
    // Request current theme from renderer to ensure menu is synced
    // Reduced delay for faster responsiveness
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.executeJavaScript(`
          (function() {
            const theme = localStorage.getItem('opcRtpmTheme') || 'light';
            if (window.electronAPI && window.electronAPI.themeReady) {
              window.electronAPI.themeReady({ theme: theme });
            }
            return theme;
          })();
        `).catch(() => {});
      }
    }, 100); // Reduced from 200ms to 100ms
  });

  // Build application menu with Help > About
  const template = [
    {
      label: 'File',
      submenu: [
        { role: 'quit' }
      ]
    },
    {
      label: 'Settings',
      submenu: [
        {
          id: 'show-current-task',
          label: 'Show Current Task',
          type: 'checkbox',
          checked: true, // Default to on
          accelerator: 'CmdOrCtrl+T',
          click: (menuItem) => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('settings:set', { showTask: !!menuItem.checked });
            }
          }
        },
      ]
    },
    {
      label: 'Themes',
      submenu: [
        {
          id: 'theme-light',
          label: 'Light Theme',
          type: 'checkbox',
          checked: true, // Default to light
          accelerator: 'CmdOrCtrl+Alt+L',
          click: (menuItem) => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              if (menuItem.checked) {
                // Uncheck dark theme if light is checked
                const menu = Menu.getApplicationMenu();
                const darkItem = menu && menu.getMenuItemById('theme-dark');
                if (darkItem) darkItem.checked = false;
                syncMenuTheme('light');
                mainWindow.webContents.send('theme:set', { theme: 'light' });
              } else {
                // If unchecking light, check dark instead
                const menu = Menu.getApplicationMenu();
                const darkItem = menu && menu.getMenuItemById('theme-dark');
                if (darkItem) {
                  darkItem.checked = true;
                  syncMenuTheme('dark');
                  mainWindow.webContents.send('theme:set', { theme: 'dark' });
                }
              }
            }
          }
        },
        {
          id: 'theme-dark',
          label: 'Dark Theme',
          type: 'checkbox',
          checked: false, // Default to unchecked (light is default)
          accelerator: 'CmdOrCtrl+Alt+D',
          click: (menuItem) => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              if (menuItem.checked) {
                // Uncheck light theme if dark is checked
                const menu = Menu.getApplicationMenu();
                const lightItem = menu && menu.getMenuItemById('theme-light');
                if (lightItem) lightItem.checked = false;
                syncMenuTheme('dark');
                mainWindow.webContents.send('theme:set', { theme: 'dark' });
              } else {
                // If unchecking dark, check light instead
                const menu = Menu.getApplicationMenu();
                const lightItem = menu && menu.getMenuItemById('theme-light');
                if (lightItem) {
                  lightItem.checked = true;
                  syncMenuTheme('light');
                  mainWindow.webContents.send('theme:set', { theme: 'light' });
                }
              }
            }
          }
        },
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'Keybinds',
          accelerator: 'CmdOrCtrl+/',
          click: () => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('show-keybinds', {});
            }
          }
        },
        {
          label: 'Repository',
          click: () => {
            try {
              shell.openExternal('https://github.com/acarioti4/OPCUA-RTPM_Diagnostic_Tool');
            } catch {
              // ignore
            }
          }
        },
        {
          label: 'About',
          accelerator: 'F1',
          click: () => {
            if (mainWindow && !mainWindow.isDestroyed()) {
              const version = typeof app.getVersion === 'function' ? app.getVersion() : '';
              mainWindow.webContents.send('show-about', { version });
            }
          }
        }
      ]
    }
  ];
  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

app.whenReady().then(createWindow);

// Open external links from renderer
ipcMain.handle('app:open-external', async (_event, url) => {
  if (typeof url === 'string' && url.trim()) {
    try {
      await shell.openExternal(url);
    } catch {
      // ignore
    }
  }
});


// Helper function to sync menu theme state (mutually exclusive checkboxes)
function syncMenuTheme(theme) {
  const menu = Menu.getApplicationMenu();
  if (!menu) return;
  const lightItem = menu.getMenuItemById('theme-light');
  const darkItem = menu.getMenuItemById('theme-dark');
  if (lightItem) {
    lightItem.checked = (theme === 'light');
  }
  if (darkItem) {
    darkItem.checked = (theme === 'dark');
  }
}

ipcMain.on('theme:ready', (_event, data = {}) => {
  const theme = data && data.theme;
  if (theme === 'light' || theme === 'dark') {
    syncMenuTheme(theme);
  } else {
    // If no valid theme received, default to light
    syncMenuTheme('light');
  }
});

// Sync menu checkbox state from renderer's persisted settings
ipcMain.on('settings:ready', (_event, data = {}) => {
  const menu = Menu.getApplicationMenu();
  if (!menu) return;
  const item = menu.getMenuItemById('show-current-task');
  if (item) {
    item.checked = !!data.showTask;
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Ensure log directory exists
const logDir = ensureLogDir();

// ----------------------------
// Helper utilities (Diagnostics)
// ----------------------------
async function listProcessListeners() {
  return new Promise((resolve) => {
    exec('netstat -ano -p tcp', { windowsHide: true }, (err, stdout) => {
      if (err) {
        resolve([]);
        return;
      }
      const listeners = parseListeningPorts(stdout);
      const myPid = String(process.pid);
      resolve(listeners.filter(l => String(l.pid) === myPid));
    });
  });
}

// Cache network interfaces (they don't change often during app lifetime)
let cachedNetworkInterfaces = null;
let networkInterfacesCacheTime = 0;
const NETWORK_INTERFACES_CACHE_TTL = 30000; // 30 seconds

function listNetworkInterfaces() {
  const now = Date.now();
  // Return cached interfaces if still valid
  if (cachedNetworkInterfaces && (now - networkInterfacesCacheTime) < NETWORK_INTERFACES_CACHE_TTL) {
    return cachedNetworkInterfaces;
  }
  
  // Refresh cache
  const ifaces = os.networkInterfaces();
  const adapters = [];
  for (const [name, entries] of Object.entries(ifaces)) {
    if (!Array.isArray(entries)) continue;
    const ipv4s = entries.filter(e => e.family === 'IPv4').map(e => ({
      address: e.address,
      netmask: e.netmask,
      mac: e.mac,
      cidr: e.cidr,
      internal: e.internal
    }));
    if (ipv4s.length) {
      adapters.push({ name, addresses: ipv4s });
    }
  }
  
  cachedNetworkInterfaces = adapters;
  networkInterfacesCacheTime = now;
  return adapters;
}

function getClientSocketInfo(client) {
  try {
    const secureChannel = client && client._secureChannel; // internal
    const transport = secureChannel && secureChannel.transport;
    const socket = transport && transport._socket;
    if (socket && typeof socket.address === 'function') {
      const local = socket.address(); // { address, family, port }
      const remoteAddress = socket.remoteAddress;
      const remotePort = socket.remotePort;
      return {
        localAddress: local.address,
        localPort: local.port,
        remoteAddress,
        remotePort
      };
    }
  } catch {
    // ignore
  }
  return null;
}

// Throttle progress updates to avoid overwhelming the renderer
let lastProgressTime = 0;
let progressThrottleMs = 100; // Update at most every 100ms
let pendingProgress = null;
let progressTimeout = null;

function sendProgress(event, payload) {
  try {
    if (!event || !event.sender) return;
    
    const now = Date.now();
    const timeSinceLastUpdate = now - lastProgressTime;
    
    // Always send if it's been long enough, or if it's a completion message
    if (timeSinceLastUpdate >= progressThrottleMs || (payload && (payload.done || payload.percent === 100))) {
      event.sender.send('diagnostics:progress', payload || {});
      lastProgressTime = now;
      pendingProgress = null;
      if (progressTimeout) {
        clearTimeout(progressTimeout);
        progressTimeout = null;
      }
    } else {
      // Throttle: store latest progress and send it later
      pendingProgress = payload;
      if (!progressTimeout) {
        const remaining = progressThrottleMs - timeSinceLastUpdate;
        progressTimeout = setTimeout(() => {
          if (pendingProgress && event && event.sender) {
            event.sender.send('diagnostics:progress', pendingProgress);
            lastProgressTime = Date.now();
            pendingProgress = null;
            progressTimeout = null;
          }
        }, remaining);
      }
    }
  } catch {
    // ignore send errors
  }
}

// Reset progress throttling for new probe
function resetProgressThrottle() {
  lastProgressTime = 0;
  pendingProgress = null;
  if (progressTimeout) {
    clearTimeout(progressTimeout);
    progressTimeout = null;
  }
}

function withTimeout(promise, ms, message = 'Operation timed out') {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), Math.max(1, ms));
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

// ---------------------------------------
// Security helpers (policy classification)
// ---------------------------------------
function extractPolicyName(policyUriOrName) {
  if (!policyUriOrName) return 'None';
  const s = String(policyUriOrName);
  const idx = s.indexOf('#');
  return idx >= 0 ? s.slice(idx + 1) : s;
}

function classifySecurityPolicy(policyUriOrName) {
  const name = extractPolicyName(policyUriOrName);
  switch (name) {
    case 'None':
      return { short: 'None', classification: 'None (insecure)' };
    case 'Basic128Rsa15':
      return { short: 'Basic128Rsa15', classification: 'Legacy/weak (avoid in production)' };
    case 'Basic256':
      return { short: 'Basic256', classification: 'Legacy RSA (better than 128, still old)' };
    case 'Basic256Sha256':
      return { short: 'Basic256Sha256', classification: 'Good RSA-SHA256' };
    case 'Aes128_Sha256_RsaOaep':
      return { short: 'AES-128', classification: 'Modern AES-128 (recommended)' };
    case 'Aes256_Sha256_RsaPss':
      return { short: 'AES-256', classification: 'Modern AES-256 (strongest, recommended)' };
    default:
      return { short: name, classification: 'Unknown policy' };
  }
}

async function monitorSynAttempts({ durationSeconds = 10, localIp, targetPorts = [], sourceHost }) {
  const events = [];
  const startTs = Date.now();
  const endTs = startTs + Math.max(1000, durationSeconds * 1000);

  // Preferred: packet capture if available
  if (CapLib && localIp && Array.isArray(targetPorts) && targetPorts.length) {
    try {
      const { Cap, decoders } = CapLib;
      const device = Cap.findDevice(localIp);
      if (device) {
        const cap = new Cap();
        const buffer = Buffer.allocUnsafe(65536);
        const filterParts = [];
        filterParts.push('tcp');
        if (targetPorts.length === 1) {
          filterParts.push(`dst port ${Number(targetPorts[0])}`);
        } else if (targetPorts.length > 1) {
          // BPF doesn't support simple array; use or-chaining
          filterParts.push('(' + targetPorts.map(p => `dst port ${Number(p)}`).join(' or ') + ')');
        }
        if (sourceHost) {
          filterParts.push(`src host ${sourceHost}`);
        }
        // SYN packets (no ACK)
        filterParts.push('(tcp[13] & 0x02 != 0)'); // SYN flag set
        const filter = filterParts.join(' and ');
        const linkType = cap.open(device, filter, 10 * 1024 * 1024, buffer);
        if (cap.setMinBytes) cap.setMinBytes(0);
        await new Promise((resolve) => {
          const onPacket = (nbytes, trunc) => {
            try {
              if (linkType === 'ETHERNET') {
                const eth = decoders.Ethernet(buffer);
                if (eth.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
                  const ipv4 = decoders.IPV4(buffer, eth.offset);
                  if (ipv4.info.protocol === decoders.PROTOCOL.IP.TCP) {
                    const tcp = decoders.TCP(buffer, ipv4.offset);
                    const ts = new Date().toISOString();
                    events.push({
                      timestamp: ts,
                      src: ipv4.info.srcaddr,
                      dst: ipv4.info.dstaddr,
                      srcPort: tcp.info.srcport,
                      dstPort: tcp.info.dstport,
                      syn: true,
                      ack: (tcp.info.flags & 0x10) !== 0,
                      trunc
                    });
                  }
                }
              }
            } catch {
              // ignore decode errors
            }
            if (Date.now() >= endTs) {
              try { cap.close(); } catch {}
              resolve();
            }
          };
          cap.on('packet', onPacket);
          const timer = setInterval(() => {
            if (Date.now() >= endTs) {
              clearInterval(timer);
              try { cap.close(); } catch {}
              resolve();
            }
          }, 1000); // Reduced check frequency from 200ms to 1000ms
        });
        return { method: 'pcap', events };
      }
    } catch {
      // fall through to netstat polling
    }
  }

  // Fallback: poll netstat for SYN-RECEIVED entries (limited visibility)
  // Optimized: reduced polling frequency from 500ms to 1000ms
  const intervalMs = 1000; // Reduced frequency for better performance
  const seenConnections = new Set(); // Deduplicate connections
  
  while (Date.now() < endTs) {
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, intervalMs));
    // eslint-disable-next-line no-await-in-loop
    const snapshot = await new Promise((resolve) => {
      exec('netstat -ano -p tcp', { windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout) => {
        if (err) {
          resolve([]);
          return;
        }
        const lines = String(stdout || '').split(/\r?\n/);
        const matches = [];
        for (const line of lines) {
          // Proto  Local Address          Foreign Address        State           PID
          const m = /^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)/i.exec(line);
          if (!m) continue;
          const localAddr = m[1];
          const localPort = Number(m[2]);
          const remoteAddr = m[3];
          const remotePort = Number(m[4]);
          const state = m[5];
          if (targetPorts.length && !targetPorts.includes(localPort)) continue;
          if (localIp && localAddr !== localIp && localAddr !== '0.0.0.0') continue;
          if (sourceHost && remoteAddr !== sourceHost) continue;
          if (/SYN/i.test(state)) {
            // Deduplicate: only add if we haven't seen this connection before
            const connKey = `${localAddr}:${localPort}-${remoteAddr}:${remotePort}`;
            if (!seenConnections.has(connKey)) {
              seenConnections.add(connKey);
              matches.push({ localAddr, localPort, remoteAddr, remotePort, state });
            }
          }
        }
        resolve(matches);
      });
    });
    if (snapshot.length) {
      const ts = new Date().toISOString();
      snapshot.forEach(s => {
        events.push({
          timestamp: ts,
          src: s.remoteAddr,
          dst: s.localAddr,
          srcPort: s.remotePort,
          dstPort: s.localPort,
          syn: true,
          ack: false,
          method: 'netstat'
        });
      });
    }
  }
  return { method: 'netstat', events };
}

// ---------------------------------------------------------
// New Diagnostics per ReadMe: Callback path verification
// ---------------------------------------------------------
ipcMain.handle('diagnostics:opcua-probe', async (event, {
  endpointUrl,
  nodeId = 'ns=0;i=2258', // ServerStatus_CurrentTime
  publishIntervalMs = 250,
  systemBHost = '',
  synMonitorSeconds = 0
} = {}) => {
  if (!endpointUrl) {
    throw new Error('endpointUrl is required (e.g., opc.tcp://<hostname>:<port>)');
  }
  if (!opcua) {
    throw new Error('node-opcua is not installed. Please run: npm install node-opcua');
  }

  const startedAt = Date.now();
  const adapters = listNetworkInterfaces();
  const probe = {
    endpointUrl,
    adapters,
    clientSocket: null,
    listenersBefore: [],
    listenersAfter: [],
    subscriptionCreated: false,
    monitoredItemNodeId: nodeId,
    synMonitor: { enabled: synMonitorSeconds > 0, method: null, events: [] },
    security: {
      endpointsQueried: false,
      advertisedAnonymous: false,
      anonymousEndpoints: [],
      anonymousSession: { success: false, error: null },
      allEndpoints: [],
      negotiatedChannel: {
        securityMode: null,
        securityPolicyUri: null,
        policyShort: null,
        classification: null,
        serverCertificateSummary: null
      }
    }
  };

  // Reset progress throttling for new probe
  resetProgressThrottle();
  
  // Initial progress
  sendProgress(event, { percent: 5, label: 'Starting…', task: 'Initializing probe…' });

  // Capture listeners before connecting
  probe.listenersBefore = await listProcessListeners();
  sendProgress(event, { percent: 10, label: 'Collecting environment…', task: 'Captured initial listeners' });

  const client = opcua.OPCUAClient.create({
    endpointMustExist: false,
    keepSessionAlive: true,
    transportSettings: {
      connectionStrategy: { maxRetry: 0 }
    }
  });

  let session = null;
  let subscription = null;
  let monitoredItem = null;
  try {
    // Connect with explicit timeout to avoid hanging indefinitely when endpoint is unreachable
    sendProgress(event, { percent: 15, label: 'Connecting…', task: 'Connecting to OPC UA server' });
    await withTimeout(client.connect(endpointUrl), 8000, 'Timeout connecting to OPC UA server');
    sendProgress(event, { percent: 35, label: 'Connected', task: 'Connected to server' });
    probe.clientSocket = getClientSocketInfo(client);

    // Get endpoints and check for anonymous user token policies
    try {
      const endpoints = await withTimeout(client.getEndpoints({ endpointUrl }), 6000, 'Timeout getting endpoints');
      probe.security.endpointsQueried = Array.isArray(endpoints) && endpoints.length > 0;
      if (Array.isArray(endpoints)) {
        const anonEndpoints = [];
        const allEndpoints = [];
        for (const ed of endpoints) {
          const tokens = Array.isArray(ed.userIdentityTokens) ? ed.userIdentityTokens : [];
          const userTokenTypes = tokens.map(t => {
            const tt = t && t.tokenType;
            const name = (opcua && opcua.UserTokenType && typeof tt === 'number') ? opcua.UserTokenType[tt] : String(tt);
            return name || 'Unknown';
          });
          const hasAnon = tokens.some(t => t.tokenType === opcua.UserTokenType.Anonymous);
          const policyUri = ed.securityPolicyUri;
          const policyInfo = classifySecurityPolicy(policyUri);
          const securityMode = String(ed.securityMode);
          allEndpoints.push({
            endpointUrl: ed.endpointUrl || endpointUrl,
            securityMode,
            securityPolicyUri: policyUri,
            policyShort: policyInfo.short,
            classification: policyInfo.classification,
            userTokens: userTokenTypes
          });
          if (hasAnon) {
            anonEndpoints.push({
              endpointUrl: ed.endpointUrl || endpointUrl,
              securityMode,
              securityPolicyUri: policyUri
            });
          }
        }
        probe.security.advertisedAnonymous = anonEndpoints.length > 0;
        probe.security.anonymousEndpoints = anonEndpoints;
        probe.security.allEndpoints = allEndpoints;
      }
    } catch (e) {
      // Endpoint query failed; continue but record
      probe.security.endpointsQueried = false;
    }

    // Try creating an anonymous session explicitly
    try {
      session = await client.createSession(); // default is Anonymous
      probe.security.anonymousSession.success = true;
      sendProgress(event, { percent: 45, label: 'Session established', task: 'Created OPC UA session (anonymous)' });

      // Capture negotiated channel security details
      try {
        const sc = client && client._secureChannel;
        if (sc) {
          const mode = String(sc.securityMode);
          const policyUri = sc.securityPolicyUri || sc.securityPolicy || null;
          const info = classifySecurityPolicy(policyUri);
          let certSummary = null;
          if (sc.serverCertificate && Buffer.isBuffer(sc.serverCertificate) && sc.serverCertificate.length) {
            // Provide a short fingerprint-like summary without heavy parsing
            const crypto = require('crypto');
            const sha1 = crypto.createHash('sha1').update(sc.serverCertificate).digest('hex').toUpperCase();
            certSummary = `len=${sc.serverCertificate.length}B sha1=${sha1.slice(0, 16)}…`;
          }
          probe.security.negotiatedChannel = {
            securityMode: mode,
            securityPolicyUri: policyUri || null,
            policyShort: info.short,
            classification: info.classification,
            serverCertificateSummary: certSummary
          };
        }
      } catch {
        // ignore
      }
    } catch (e) {
      probe.security.anonymousSession.success = false;
      probe.security.anonymousSession.error = e && (e.message || String(e));
      // Cannot proceed with subscription if session failed; disconnect and finish
      try { await client.disconnect(); } catch {}
      // Advance progress to completion with warning
      sendProgress(event, { percent: 100, label: 'Completed', task: 'Anonymous session not allowed; security info captured', done: true, success: false });
      // Write log and return early
      const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
      const logFileName = `opcua-rtpm-diagnostic-tool_${timestamp}.log`;
      const logPath = path.join(logDir, logFileName);
      const lines = [];
      lines.push('='.repeat(80));
      lines.push('OPCUA-RTPM DIAGNOSTIC TOOL');
      lines.push('='.repeat(80));
      lines.push(`When: ${new Date().toISOString()}`);
      lines.push(`EndpointUrl: ${probe.endpointUrl}`);
      lines.push(`DurationMs: ${Date.now() - startedAt}`);
      lines.push('-'.repeat(80));
      lines.push('Endpoint Security:');
      lines.push(`EndpointsQueried: ${probe.security.endpointsQueried ? 'yes' : 'no'}`);
      lines.push(`AdvertisedAnonymous: ${probe.security.advertisedAnonymous ? 'yes' : 'no'}`);
      if (probe.security.endpointsQueried && probe.security.allEndpoints.length) {
        lines.push('All Discovered Endpoints:');
        probe.security.allEndpoints.forEach((ed, idx) => {
          lines.push(`  [${idx + 1}] ${ed.endpointUrl} mode=${ed.securityMode} policy=${ed.securityPolicyUri} (${ed.policyShort}; ${ed.classification}); tokens=${ed.userTokens.join(',')}`);
        });
      }
      if (probe.security.anonymousEndpoints.length) {
        probe.security.anonymousEndpoints.forEach((ed, idx) => {
          lines.push(`  [${idx + 1}] ${ed.endpointUrl} mode=${ed.securityMode} policy=${ed.securityPolicyUri}`);
        });
      }
      lines.push(`AnonymousSession: ${probe.security.anonymousSession.success ? 'success' : 'failed'}`);
      if (probe.security.anonymousSession.error) {
        lines.push(`AnonymousSessionError: ${probe.security.anonymousSession.error}`);
      }
      if (probe.security.negotiatedChannel && (probe.security.negotiatedChannel.securityMode || probe.security.negotiatedChannel.securityPolicyUri)) {
        lines.push(`NegotiatedChannel: mode=${probe.security.negotiatedChannel.securityMode} policy=${probe.security.negotiatedChannel.securityPolicyUri} (${probe.security.negotiatedChannel.policyShort}; ${probe.security.negotiatedChannel.classification})`);
        if (probe.security.negotiatedChannel.serverCertificateSummary) {
          lines.push(`NegotiatedChannelServerCert: ${probe.security.negotiatedChannel.serverCertificateSummary}`);
        }
      }
      lines.push('-'.repeat(80));
      lines.push('Client Callback Info:');
      if (probe.clientSocket) {
        lines.push(`Local: ${probe.clientSocket.localAddress}:${probe.clientSocket.localPort}`);
        lines.push(`Remote: ${probe.clientSocket.remoteAddress}:${probe.clientSocket.remotePort}`);
      } else {
        lines.push('Local: (unavailable)');
      }
      lines.push('-'.repeat(80));
      lines.push('System A Network Interfaces:');
      adapters.forEach(a => {
        lines.push(`Adapter: ${a.name}`);
        a.addresses.forEach(addr => lines.push(`  ${addr.address} cidr=${addr.cidr} mac=${addr.mac}`));
      });
      // Write log asynchronously with error handling
      const logContent = lines.join('\n');
      try {
        await new Promise((resolve, reject) => {
          fs.writeFile(logPath, logContent, 'utf8', (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      } catch (logError) {
        // Log write failed, but don't fail the probe
        console.error('Failed to write log file:', logError);
        // Continue without failing
      } finally {
        // Cleanup progress throttling
        resetProgressThrottle();
      }
      return { probe, logPath, logFileName };
    }

    // Create a subscription to force server->client publish activity over the secure channel
    subscription = opcua.ClientSubscription.create(session, {
      requestedPublishingInterval: Math.max(50, Number(publishIntervalMs) || 250),
      requestedLifetimeCount: 100,
      requestedMaxKeepAliveCount: 20,
      maxNotificationsPerPublish: 1000,
      publishingEnabled: true,
      priority: 10
    });
    probe.subscriptionCreated = true;
    sendProgress(event, { percent: 55, label: 'Subscribed', task: 'Created subscription' });

    const itemToMonitor = {
      nodeId: opcua.resolveNodeId(nodeId),
      attributeId: opcua.AttributeIds.Value
    };
    const parameters = {
      samplingInterval: 1000,
      discardOldest: true,
      queueSize: 10
    };
    monitoredItem = opcua.ClientMonitoredItem.create(
      subscription,
      itemToMonitor,
      parameters,
      opcua.TimestampsToReturn.Both
    );

    // Wait briefly to allow any sockets/listeners to initialize
    sendProgress(event, { percent: 60, label: 'Preparing…', task: 'Waiting for server activity' });
    await new Promise(r => setTimeout(r, 1500));

    // Capture listeners after creating subscription
    probe.listenersAfter = await listProcessListeners();
    sendProgress(event, { percent: 65, label: 'Collecting environment…', task: 'Captured listeners after subscription' });

    // Optionally monitor for SYN attempts from System B to any new listeners
    if (synMonitorSeconds > 0) {
      const candidatePorts = probe.listenersAfter
        .filter(l => !probe.listenersBefore.some(b => b.localPort === l.localPort))
        .map(l => Number(l.localPort));

      // If no new listeners appeared, still allow monitoring known listeners
      const targetPorts = candidatePorts.length ? candidatePorts : probe.listenersAfter.map(l => Number(l.localPort));

      let localIp = probe.clientSocket && probe.clientSocket.localAddress;
      // If client socket not available, pick first non-internal adapter
      if (!localIp && adapters.length && adapters[0].addresses.length) {
        localIp = adapters[0].addresses[0].address;
      }

      // Progress during SYN monitoring (65% -> 95%)
      // Optimized: reduced progress update frequency
      const monitorStart = Date.now();
      const monitorTotalMs = Math.max(1000, synMonitorSeconds * 1000);
      sendProgress(event, { percent: 66, label: 'Monitoring connections…', task: 'Listening for SYN attempts' });
      let progressTimer = null;
      try {
        progressTimer = setInterval(() => {
          const elapsed = Date.now() - monitorStart;
          const frac = Math.min(1, elapsed / monitorTotalMs);
          const p = 66 + Math.floor(frac * (95 - 66));
          sendProgress(event, { percent: p, label: 'Monitoring connections…', task: 'Listening for SYN attempts' });
        }, 1000); // Reduced from 500ms to 1000ms for better performance

        const { method, events } = await monitorSynAttempts({
          durationSeconds: synMonitorSeconds,
          localIp,
          targetPorts,
          sourceHost: systemBHost || undefined
        });
        probe.synMonitor.method = method;
        probe.synMonitor.events = events;
        sendProgress(event, { percent: 95, label: 'Monitoring complete', task: `${events.length} attempt(s) captured` });
      } finally {
        // Always cleanup progress timer
        if (progressTimer) {
          clearInterval(progressTimer);
          progressTimer = null;
        }
      }
    }

    // Clean up monitored item and subscription
    try { 
      if (monitoredItem) await monitoredItem.terminate(); 
      monitoredItem = null;
    } catch {}
    try { 
      if (subscription) await subscription.terminate(); 
      subscription = null;
    } catch {}
    try { 
      if (session) await session.close(); 
      session = null;
    } catch {}
    try { 
      if (client) await client.disconnect(); 
      client = null;
    } catch {}
  } catch (e) {
    // Attempt graceful cleanup
    try { 
      if (monitoredItem) await monitoredItem.terminate(); 
      monitoredItem = null;
    } catch {}
    try { 
      if (subscription) await subscription.terminate(); 
      subscription = null;
    } catch {}
    try { 
      if (session) await session.close(); 
      session = null;
    } catch {}
    try { 
      if (client) await client.disconnect(); 
      client = null;
    } catch {}
    probe.error = e && (e.message || String(e));
    sendProgress(event, { percent: 100, label: 'Failed', task: probe.error || 'Probe failed', done: true, success: false });
  } finally {
    // Cleanup progress throttling
    resetProgressThrottle();
  }

  // Write structured log asynchronously to avoid blocking
  const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
  const logFileName = `opcua-rtpm-diagnostic-tool_${timestamp}.log`;
  const logPath = path.join(logDir, logFileName);
  
  // Build log content asynchronously
  const buildLogContent = () => {
    const lines = [];
    lines.push('='.repeat(80));
    lines.push('OPCUA-RTPM DIAGNOSTIC TOOL');
    lines.push('='.repeat(80));
    lines.push(`When: ${new Date().toISOString()}`);
    lines.push(`EndpointUrl: ${probe.endpointUrl}`);
    lines.push(`DurationMs: ${Date.now() - startedAt}`);
    lines.push('-'.repeat(80));
    lines.push('Endpoint Security:');
    lines.push(`EndpointsQueried: ${probe.security.endpointsQueried ? 'yes' : 'no'}`);
    lines.push(`AdvertisedAnonymous: ${probe.security.advertisedAnonymous ? 'yes' : 'no'}`);
    if (probe.security.endpointsQueried && probe.security.allEndpoints.length) {
      lines.push('All Discovered Endpoints:');
      probe.security.allEndpoints.forEach((ed, idx) => {
        lines.push(`  [${idx + 1}] ${ed.endpointUrl} mode=${ed.securityMode} policy=${ed.securityPolicyUri} (${ed.policyShort}; ${ed.classification}); tokens=${ed.userTokens.join(',')}`);
      });
    }
    if (probe.security.anonymousEndpoints.length) {
      probe.security.anonymousEndpoints.forEach((ed, idx) => {
        lines.push(`  [${idx + 1}] ${ed.endpointUrl} mode=${ed.securityMode} policy=${ed.securityPolicyUri}`);
      });
    }
    lines.push(`AnonymousSession: ${probe.security.anonymousSession.success ? 'success' : 'failed'}`);
    if (probe.security.anonymousSession.error) {
      lines.push(`AnonymousSessionError: ${probe.security.anonymousSession.error}`);
    }
    if (probe.security.negotiatedChannel && (probe.security.negotiatedChannel.securityMode || probe.security.negotiatedChannel.securityPolicyUri)) {
      lines.push(`NegotiatedChannel: mode=${probe.security.negotiatedChannel.securityMode} policy=${probe.security.negotiatedChannel.securityPolicyUri} (${probe.security.negotiatedChannel.policyShort}; ${probe.security.negotiatedChannel.classification})`);
      if (probe.security.negotiatedChannel.serverCertificateSummary) {
        lines.push(`NegotiatedChannelServerCert: ${probe.security.negotiatedChannel.serverCertificateSummary}`);
      }
    }
    lines.push('-'.repeat(80));
    lines.push('Client Callback Info:');
    if (probe.clientSocket) {
      lines.push(`Local: ${probe.clientSocket.localAddress}:${probe.clientSocket.localPort}`);
      lines.push(`Remote: ${probe.clientSocket.remoteAddress}:${probe.clientSocket.remotePort}`);
    } else {
      lines.push('Local: (unavailable)');
    }
    lines.push('-'.repeat(80));
    lines.push('System A Network Interfaces:');
    adapters.forEach(a => {
      lines.push(`Adapter: ${a.name}`);
      a.addresses.forEach(addr => lines.push(`  ${addr.address} cidr=${addr.cidr} mac=${addr.mac}`));
    });
    lines.push('-'.repeat(80));
    lines.push('Process Listening Ports (before):');
    if (!probe.listenersBefore.length) {
      lines.push('  (none)');
    } else {
      probe.listenersBefore.forEach(l => lines.push(`  ${l.localAddress}:${l.localPort} pid=${l.pid}`));
    }
    lines.push('Process Listening Ports (after subscription):');
    if (!probe.listenersAfter.length) {
      lines.push('  (none)');
    } else {
      probe.listenersAfter.forEach(l => lines.push(`  ${l.localAddress}:${l.localPort} pid=${l.pid}`));
    }
    if (probe.synMonitor.enabled) {
      lines.push('-'.repeat(80));
      lines.push(`Connection Attempt Logger: method=${probe.synMonitor.method || 'none'}`);
      if (!probe.synMonitor.events.length) {
        lines.push('  No SYN attempts captured');
      } else {
        probe.synMonitor.events.forEach(ev => {
          lines.push(`  [${ev.timestamp}] ${ev.src}:${ev.srcPort} -> ${ev.dst}:${ev.dstPort} syn=${ev.syn} ack=${ev.ack || false}`);
        });
      }
    }
    if (probe.error) {
      lines.push('-'.repeat(80));
      lines.push(`Error: ${probe.error}`);
    }
    return lines.join('\n');
  };
  
  // Write log asynchronously (non-blocking) with error handling
  const logContent = buildLogContent();
  try {
    await new Promise((resolve, reject) => {
      fs.writeFile(logPath, logContent, 'utf8', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  } catch (logError) {
    // Log write failed, but don't fail the probe
    console.error('Failed to write log file:', logError);
    // Continue without failing
  }

  if (!probe.error) {
    sendProgress(event, { percent: 100, label: 'Completed', task: 'Probe complete', done: true, success: true });
  }

  return { probe, logPath, logFileName };
});

// end of file