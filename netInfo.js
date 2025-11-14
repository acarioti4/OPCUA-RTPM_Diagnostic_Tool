// netInfo.js
const { exec } = require('child_process');
const os = require('os');
const { parseListeningPorts } = require('./netstat');

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

module.exports = {
  listProcessListeners,
  listNetworkInterfaces,
  getClientSocketInfo
};


