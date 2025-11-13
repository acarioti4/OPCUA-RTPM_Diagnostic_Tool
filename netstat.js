const { exec } = require('child_process');

function parseConnectionsByLocalPort(text, targetPort) {
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
}

function parseNetstatForTarget(text, remoteHost, remotePort) {
  const lines = text.split(/\r?\n/);
  const re = /^\s*TCP\s+([^\s:]+):(\d+)\s+([^\s:]+):(\d+)\s+(\S+)\s+(\d+)/i;
  const matches = [];
  for (const line of lines) {
    const m = re.exec(line);
    if (!m) continue;
    const localAddr = m[1];
    const localPort = Number(m[2]);
    const foreignAddr = m[3];
    const foreignPort = Number(m[4]);
    const state = m[5];
    const pid = Number(m[6]);
    if (foreignAddr === remoteHost && foreignPort === Number(remotePort)) {
      matches.push({ localAddress: localAddr, localPort, remoteAddress: foreignAddr, remotePort: foreignPort, state, pid });
    }
  }
  return matches;
}

function pidToNameMap(pids) {
  const unique = Array.from(new Set(pids.filter((p) => Number.isFinite(p))));
  const map = {};
  return Promise.all(unique.map((pid) => new Promise((resolve) => {
    exec(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { windowsHide: true }, (err, stdout) => {
      if (!err) {
        const m = /"([^"]+)"\s*,\s*"(\d+)"/.exec(stdout);
        if (m) {
          map[pid] = m[1];
        }
      }
      resolve();
    });
  }))).then(() => map);
}

module.exports = {
  parseConnectionsByLocalPort,
  parseNetstatForTarget,
  pidToNameMap
};


