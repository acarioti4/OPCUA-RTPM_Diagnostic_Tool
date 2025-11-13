// main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const net = require('net');
const fs = require('fs');
const { exec } = require('child_process');

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
const logDir = path.join(app.getPath('userData'), 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Test a single port
function testPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let connected = false;

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      connected = true;
      socket.destroy();
      resolve({
        port,
        status: 'open',
        message: 'Connection successful - Port is open and accepting connections'
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        port,
        status: 'timeout',
        message: 'Connection timeout - Port may be filtered or host is unreachable'
      });
    });

    socket.on('error', (err) => {
      let message = '';
      if (err.code === 'ECONNREFUSED') {
        message = 'Connection refused - Port is closed or service is not running';
      } else if (err.code === 'EHOSTUNREACH') {
        message = 'Host unreachable - Check network connectivity';
      } else if (err.code === 'ENETUNREACH') {
        message = 'Network unreachable - Check routing or firewall settings';
      } else {
        message = `Error: ${err.code || err.message}`;
      }
      
      resolve({
        port,
        status: 'closed',
        message,
        error: err.code
      });
    });

    socket.connect(port, host);
  });
}

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
  const parseConnections = (text, targetPort) => {
    const lines = text.split(/\r?\n/);
    const conns = [];
    const re = /^\s*TCP\s+([^\s:]+):(\d+)\s+([^\s:]+):(\d+)\s+(\S+)\s+(\d+)/i;
    for (const line of lines) {
      const m = re.exec(line);
      if (!m) continue;
      const localAddr = m[1];
      const localPort = Number(m[2]);
      const remoteAddr = m[3];
      const remotePort = Number(m[4]);
      const state = m[5];
      if (localPort === Number(targetPort) && ['ESTABLISHED', 'SYN_RECEIVED', 'SYN_SENT'].includes(state)) {
        conns.push({ localAddress: localAddr, localPort, remoteAddress: remoteAddr, remotePort, state });
      }
    }
    // Deduplicate by remoteAddress:remotePort
    const seen = new Set();
    const unique = [];
    for (const c of conns) {
      const k = `${c.remoteAddress}:${c.remotePort}`;
      if (!seen.has(k)) {
        seen.add(k);
        unique.push(c);
      }
    }
    return unique;
  };

  // Windows netstat output
  const cmd = 'netstat -ano -p tcp';
  return new Promise((resolve) => {
    exec(cmd, { windowsHide: true }, (err, stdout) => {
      if (err) {
        resolve({ connections: [], error: err.message });
        return;
      }
      const connections = parseConnections(stdout, serverPort);
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

  function createHelloBuffer(epUrl) {
    // Build HELF header + body per OPC UA TCP
    const endpointBytes = Buffer.from(epUrl, 'utf8');
    const stringLen = Buffer.alloc(4);
    stringLen.writeInt32LE(endpointBytes.length, 0);

    const body = Buffer.alloc(20); // 5x UInt32
    // protocolVersion
    body.writeUInt32LE(0, 0);
    // receiveBufferSize
    body.writeUInt32LE(16384, 4);
    // sendBufferSize
    body.writeUInt32LE(16384, 8);
    // maxMessageSize (0 = unlimited)
    body.writeUInt32LE(0, 12);
    // maxChunkCount (0 = unlimited)
    body.writeUInt32LE(0, 16);

    const header = Buffer.alloc(8);
    header.write('HELF', 0, 'ascii'); // MessageType 'HEL' + 'F' chunk

    const totalLen = header.length + body.length + stringLen.length + endpointBytes.length;
    header.writeUInt32LE(totalLen, 4);

    return Buffer.concat([header, body, stringLen, endpointBytes]);
  }

  function parseAckHeader(buf) {
    if (buf.length < 8) return { ok: false, message: 'Incomplete response header' };
    const msgType = buf.slice(0, 3).toString('ascii');
    const chunkType = buf.slice(3, 4).toString('ascii');
    const length = buf.readUInt32LE(4);
    return { msgType, chunkType, length };
  }

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

// Concurrent port testing with limit
function testPortsConcurrent(host, startPort, endPort, concurrency = 100, onProgress) {
  const totalPorts = endPort - startPort + 1;
  const ports = [];
  for (let p = startPort; p <= endPort; p++) {
    ports.push(p);
  }

  const results = new Array(totalPorts);
  let inFlight = 0;
  let nextIndex = 0;
  let completed = 0;

  return new Promise((resolve) => {
    function launchMore() {
      while (inFlight < concurrency && nextIndex < totalPorts) {
        const currentIndex = nextIndex++;
        const port = ports[currentIndex];
        inFlight++;

        testPort(host, port).then((result) => {
          results[currentIndex] = result;
          completed++;
          if (onProgress) {
            onProgress({
              current: completed,
              total: totalPorts,
              result
            });
          }
        }).finally(() => {
          inFlight--;
          if (completed === totalPorts) {
            resolve(results);
          } else {
            launchMore();
          }
        });
      }
    }

    launchMore();
  });
}

function generateLogContent(host, startPort, endPort, results) {
  const timestamp = new Date().toISOString();
  const openPorts = results.filter(r => r.status === 'open');
  const closedPorts = results.filter(r => r.status === 'closed');
  const timeoutPorts = results.filter(r => r.status === 'timeout');

  let content = '='.repeat(80) + '\n';
  content += 'OPC UA SERVER TO RTPM SERVER - TCP CONNECTIVITY TEST\n';
  content += '='.repeat(80) + '\n\n';
  content += `Test Date/Time: ${timestamp}\n`;
  content += `Target Host: ${host}\n`;
  content += `Port Range: ${startPort}-${endPort}\n`;
  content += `Total Ports Tested: ${results.length}\n\n`;

  content += 'SUMMARY\n';
  content += '-'.repeat(80) + '\n';
  content += `Open Ports: ${openPorts.length}\n`;
  content += `Closed Ports: ${closedPorts.length}\n`;
  content += `Timeout/Filtered: ${timeoutPorts.length}\n\n`;

  if (openPorts.length > 0) {
    content += 'SUCCESSFUL CONNECTIONS (OPEN PORTS)\n';
    content += '-'.repeat(80) + '\n';
    openPorts.forEach(p => {
      content += `Port ${p.port}: ${p.message}\n`;
    });
    content += '\n';
  }

  if (closedPorts.length > 0) {
    content += 'FAILED CONNECTIONS (CLOSED PORTS)\n';
    content += '-'.repeat(80) + '\n';
    closedPorts.forEach(p => {
      content += `Port ${p.port}: ${p.message}\n`;
    });
    content += '\n';
  }

  if (timeoutPorts.length > 0) {
    content += 'TIMEOUT/FILTERED PORTS\n';
    content += '-'.repeat(80) + '\n';
    timeoutPorts.forEach(p => {
      content += `Port ${p.port}: ${p.message}\n`;
    });
    content += '\n';
  }

  content += 'DETAILED RESULTS\n';
  content += '-'.repeat(80) + '\n';
  results.forEach(r => {
    content += `[${r.status.toUpperCase()}] Port ${r.port}: ${r.message}\n`;
  });

  return content;
}