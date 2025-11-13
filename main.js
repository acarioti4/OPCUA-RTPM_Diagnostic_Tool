// main.js
const { app, BrowserWindow, ipcMain, Menu } = require('electron');
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
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile('index.html');

  // Build application menu with Help > About
  const template = [
    // App/Menu skeleton (keep default File/Edit/View where possible via roles)
    {
      label: 'File',
      submenu: [
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About',
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

function listNetworkInterfaces() {
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
          }, 200);
        });
        return { method: 'pcap', events };
      }
    } catch {
      // fall through to netstat polling
    }
  }

  // Fallback: poll netstat for SYN-RECEIVED entries (limited visibility)
  const intervalMs = 500;
  while (Date.now() < endTs) {
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, intervalMs));
    // eslint-disable-next-line no-await-in-loop
    const snapshot = await new Promise((resolve) => {
      exec('netstat -ano -p tcp', { windowsHide: true }, (err, stdout) => {
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
            matches.push({ localAddr, localPort, remoteAddr, remotePort, state });
          }
        }
        resolve(matches);
      });
    });
    if (snapshot.length) {
      const ts = new Date().toISOString();
      snapshot.forEach(s => events.push({
        timestamp: ts,
        src: s.remoteAddr,
        dst: s.localAddr,
        srcPort: s.remotePort,
        dstPort: s.localPort,
        syn: true,
        ack: false,
        method: 'netstat'
      }));
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
    synMonitor: { enabled: synMonitorSeconds > 0, method: null, events: [] }
  };

  // Capture listeners before connecting
  probe.listenersBefore = await listProcessListeners();

  const client = opcua.OPCUAClient.create({
    endpointMustExist: false,
    keepSessionAlive: true,
    transportSettings: {
      connectionStrategy: { maxRetry: 0 }
    }
  });

  let session = null;
  let subscription = null;
  try {
    await client.connect(endpointUrl);
    probe.clientSocket = getClientSocketInfo(client);

    session = await client.createSession();

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

    const itemToMonitor = {
      nodeId: opcua.resolveNodeId(nodeId),
      attributeId: opcua.AttributeIds.Value
    };
    const parameters = {
      samplingInterval: 1000,
      discardOldest: true,
      queueSize: 10
    };
    const monitoredItem = opcua.ClientMonitoredItem.create(
      subscription,
      itemToMonitor,
      parameters,
      opcua.TimestampsToReturn.Both
    );

    // Wait briefly to allow any sockets/listeners to initialize
    await new Promise(r => setTimeout(r, 1500));

    // Capture listeners after creating subscription
    probe.listenersAfter = await listProcessListeners();

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

      const { method, events } = await monitorSynAttempts({
        durationSeconds: synMonitorSeconds,
        localIp,
        targetPorts,
        sourceHost: systemBHost || undefined
      });
      probe.synMonitor.method = method;
      probe.synMonitor.events = events;
    }

    // Clean up monitored item and subscription
    try { await monitoredItem.terminate(); } catch {}
    try { await subscription.terminate(); } catch {}
    try { await session.close(); } catch {}
    try { await client.disconnect(); } catch {}
  } catch (e) {
    // Attempt graceful cleanup
    try { if (subscription) await subscription.terminate(); } catch {}
    try { if (session) await session.close(); } catch {}
    try { await client.disconnect(); } catch {}
    probe.error = e && (e.message || String(e));
  }

  // Write structured log
  const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
  const logFileName = `opcua-callback-probe_${timestamp}.log`;
  const logPath = path.join(logDir, logFileName);
  const lines = [];
  lines.push('='.repeat(80));
  lines.push('OPC UA CALLBACK PATH PROBE');
  lines.push('='.repeat(80));
  lines.push(`When: ${new Date().toISOString()}`);
  lines.push(`EndpointUrl: ${probe.endpointUrl}`);
  lines.push(`DurationMs: ${Date.now() - startedAt}`);
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
  fs.writeFileSync(logPath, lines.join('\n'));

  return { probe, logPath, logFileName };
});

// end of file