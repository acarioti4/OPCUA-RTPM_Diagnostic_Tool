// main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const net = require('net');
const fs = require('fs');
const { exec } = require('child_process');
const { ensureLogDir, generateLogContent } = require('./logs');
const { testPort, testPortsConcurrent } = require('./portScan');
const { createHelloBuffer, parseAckHeader } = require('./opcuaHello');
const { parseConnectionsByLocalPort, parseNetstatForTarget, pidToNameMap } = require('./netstat');

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

  mainWindow.loadFile('UI.html');
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

// Handle port testing request
ipcMain.handle('test-ports', async (event, { host, startPort, endPort, concurrency }) => {
  const results = await testPortsConcurrent(
    host, 
    startPort, 
    endPort, 
    Math.max(1, Math.min(Number(concurrency) || 100, 500)), 
    (progress) => {
      event.sender.send('test-progress', progress);
    }
  );

  // Generate log
  const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
  const logFileName = `tcp-test_${host}_${timestamp}.log`;
  const logPath = path.join(logDir, logFileName);

  const logContent = generateLogContent(host, startPort, endPort, results);
  fs.writeFileSync(logPath, logContent);

  return {
    results,
    logPath,
    logFileName
  };
});

// Detect active client connections to local OPC UA Server port (e.g., Kepware 4840)
ipcMain.handle('detect-service', async (event, { serverPort = 4840 } = {}) => {
  // Windows netstat output
  const cmd = 'netstat -ano -p tcp';
  return new Promise((resolve) => {
    exec(cmd, { windowsHide: true }, (err, stdout) => {
      if (err) {
        resolve({ connections: [], error: err.message });
        return;
      }
      const connections = parseConnectionsByLocalPort(stdout, serverPort);
      resolve({ connections });
    });
  });
});

// Send minimal OPC UA TCP Hello and await Acknowledge (ACK)
ipcMain.handle('opc-hello-test', async (event, { host, port, endpointUrl } = {}) => {
  if (!host || !port) {
    throw new Error('host and port are required');
  }
  const url = endpointUrl || `opc.tcp://${host}:${port}`;

  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timeoutMs = 4000;
    let settled = false;

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolve(payload);
    };

    socket.setTimeout(timeoutMs);
    socket.once('timeout', () => finish({ ok: false, error: 'timeout', message: 'Timeout waiting for ACK' }));
    socket.once('error', (err) => finish({ ok: false, error: err.code || 'error', message: err.message }));

    socket.connect(Number(port), host, () => {
      const hello = createHelloBuffer(url);
      socket.write(hello);
    });

    socket.once('data', (data) => {
      const h = parseAckHeader(data);
      if (h.msgType === 'ACK' && h.chunkType === 'F') {
        finish({ ok: true, message: 'Received OPC UA Acknowledge (ACK)', header: h });
      } else if (h.msgType === 'ERR') {
        finish({ ok: false, error: 'OPC-UA-ERROR', message: 'Received OPC UA ERR response', header: h });
      } else {
        finish({ ok: false, error: 'unexpected', message: `Unexpected response: ${h.msgType || 'unknown'}`, header: h });
      }
    });
  });
});

// Generic TCP connect + optional payload send + optional response read
ipcMain.handle('tcp-send-test', async (event, {
  host,
  port,
  payload = '',
  encoding = 'text', // 'text' | 'hex'
  expectResponse = true,
  readTimeoutMs = 3000,
  maxBytes = 4096
} = {}) => {
  if (!host || !port) {
    throw new Error('host and port are required');
  }

  function makeBuffer(data, enc) {
    if (!data) return Buffer.alloc(0);
    if (enc === 'hex') {
      return Buffer.from(data.replace(/\s+/g, ''), 'hex');
    }
    return Buffer.from(String(data), 'utf8');
  }

  const startTs = Date.now();
  const txBuffer = makeBuffer(payload, encoding);

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let timer = null;
    let received = Buffer.alloc(0);
    let connectedAt = null;

    const finalize = (res) => {
      try { if (timer) clearTimeout(timer); } catch {}
      try { socket.destroy(); } catch {}

      // Persist log
      const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
      const logFileName = `tcp-send_${host}_${port}_${timestamp}.log`;
      const logPath = path.join(logDir, logFileName);

      const lines = [];
      lines.push('='.repeat(80));
      lines.push('MY SERVICE TCP LISTENER TEST');
      lines.push('='.repeat(80));
      lines.push(`When: ${new Date().toISOString()}`);
      lines.push(`Target: ${host}:${port}`);
      lines.push(`Connected: ${res.connected ? 'yes' : 'no'}`);
      lines.push(`ConnectMs: ${res.connectMs ?? 'n/a'}`);
      lines.push(`SentBytes: ${res.sentBytes}`);
      lines.push(`ExpectResponse: ${expectResponse}`);
      lines.push(`ReceivedBytes: ${res.receivedBytes}`);
      if (res.responseHex) lines.push(`ResponseHex: ${res.responseHex}`);
      if (res.responseText) lines.push(`ResponseText: ${res.responseText}`);
      if (res.error) lines.push(`Error: ${res.error}`);
      fs.writeFileSync(logPath, lines.join('\n'));

      resolve({ ...res, logPath, logFileName });
    };

    const onTimeout = () => {
      finalize({
        ok: txBuffer.length === 0 ? true : true,
        connected: Boolean(connectedAt),
        connectMs: connectedAt ? (connectedAt - startTs) : undefined,
        sentBytes: txBuffer.length,
        receivedBytes: received.length,
        responseHex: received.length ? received.toString('hex') : '',
        responseText: received.length ? received.toString('utf8') : '',
        message: 'Completed with timeout while waiting for response'
      });
    };

    socket.setTimeout(Math.max(1000, readTimeoutMs));
    socket.once('timeout', onTimeout);

    socket.once('error', (err) => {
      finalize({
        ok: false,
        connected: Boolean(connectedAt),
        connectMs: connectedAt ? (connectedAt - startTs) : undefined,
        sentBytes: txBuffer.length,
        receivedBytes: received.length,
        responseHex: received.length ? received.toString('hex') : '',
        responseText: received.length ? received.toString('utf8') : '',
        error: err.code || err.message
      });
    });

    socket.connect(Number(port), host, () => {
      connectedAt = Date.now();
      socket.setNoDelay(true);
      if (txBuffer.length) {
        socket.write(txBuffer);
      }
      if (!expectResponse) {
        timer = setTimeout(() => {
          finalize({
            ok: true,
            connected: true,
            connectMs: connectedAt - startTs,
            sentBytes: txBuffer.length,
            receivedBytes: 0,
            responseHex: '',
            responseText: '',
            message: 'Sent without waiting for response'
          });
        }, Math.max(200, readTimeoutMs));
      }
    });

    socket.on('data', (chunk) => {
      if (!expectResponse) return;
      received = Buffer.concat([received, chunk]);
      if (received.length >= maxBytes) {
        finalize({
          ok: true,
          connected: true,
          connectMs: connectedAt ? (connectedAt - startTs) : undefined,
          sentBytes: txBuffer.length,
          receivedBytes: received.length,
          responseHex: received.toString('hex'),
          responseText: received.toString('utf8'),
          message: 'Received max bytes'
        });
      } else {
        // refresh timeout window
        try { if (timer) clearTimeout(timer); } catch {}
        timer = setTimeout(onTimeout, Math.max(200, readTimeoutMs));
      }
    });
  });
});

// Monitor outbound TCP connections to a specific remote host:port for a short window
ipcMain.handle('monitor-outbound', async (event, {
  remoteHost,
  remotePort,
  durationSeconds = 10,
  intervalMs = 1000
} = {}) => {
  if (!remoteHost || !remotePort) {
    throw new Error('remoteHost and remotePort are required');
  }
  const samples = [];
  const started = Date.now();

  async function snapshot() {
    return new Promise((resolve) => {
      exec('netstat -ano -p tcp', { windowsHide: true }, async (err, stdout) => {
        if (err) return resolve({ timestamp: Date.now(), connections: [] });
        const conns = parseNetstatForTarget(stdout, remoteHost, remotePort);
        const pidMap = await pidToNameMap(conns.map(c => c.pid));
        conns.forEach(c => { c.process = pidMap[c.pid] || ''; });
        resolve({ timestamp: Date.now(), connections: conns });
      });
    });
  }

  const endTime = started + Math.max(1000, durationSeconds * 1000);
  while (Date.now() < endTime) {
    // eslint-disable-next-line no-await-in-loop
    const s = await snapshot();
    samples.push(s);
    // sleep
    // eslint-disable-next-line no-await-in-loop
    await new Promise(r => setTimeout(r, Math.max(200, intervalMs)));
  }

  // Write log
  const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
  const logFileName = `monitor-outbound_${remoteHost}_${remotePort}_${timestamp}.log`;
  const logPath = path.join(logDir, logFileName);
  const lines = [];
  lines.push('='.repeat(80));
  lines.push('OUTBOUND CONNECTION MONITOR');
  lines.push('='.repeat(80));
  lines.push(`When: ${new Date().toISOString()}`);
  lines.push(`Target: ${remoteHost}:${remotePort}`);
  for (const s of samples) {
    lines.push('-'.repeat(80));
    lines.push(`t=${new Date(s.timestamp).toISOString()}`);
    if (!s.connections.length) {
      lines.push('No matching connections');
    } else {
      s.connections.forEach(c => {
        lines.push(`${c.localAddress}:${c.localPort} -> ${c.remoteAddress}:${c.remotePort} [${c.state}] pid=${c.pid} ${c.process || ''}`);
      });
    }
  }
  fs.writeFileSync(logPath, lines.join('\n'));

  return { samples, logPath, logFileName };
});

// end of file