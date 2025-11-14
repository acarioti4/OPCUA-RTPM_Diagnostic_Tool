// synCapture.js
const { exec } = require('child_process');

function optionalCap() {
  try {
    // eslint-disable-next-line global-require
    return require('cap');
  } catch {
    return null;
  }
}

async function monitorSynAttempts({ durationSeconds = 10, localIp, targetPorts = [], sourceHost }) {
  const events = [];
  const startTs = Date.now();
  const endTs = startTs + Math.max(1000, durationSeconds * 1000);

  const CapLib = optionalCap();
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
          filterParts.push('(' + targetPorts.map(p => `dst port ${Number(p)}`).join(' or ') + ')');
        }
        if (sourceHost) {
          filterParts.push(`src host ${sourceHost}`);
        }
        // SYN packets (no ACK)
        filterParts.push('(tcp[13] & 0x02 != 0)');
        const filter = filterParts.join(' and ');
        const linkType = cap.open(device, filter, 10 * 1024 * 1024, buffer);
        if (cap.setMinBytes) cap.setMinBytes(0);
        await new Promise((resolve) => {
          const onPacket = () => {
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
                      ack: (tcp.info.flags & 0x10) !== 0
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
          let timer = null;
          try {
            timer = setInterval(() => {
              if (Date.now() >= endTs) {
                if (timer) {
                  clearInterval(timer);
                  timer = null;
                }
                try { cap.close(); } catch {}
                resolve();
              }
            }, 1000); // Reduced check frequency from 200ms to 1000ms
          } catch (err) {
            // Cleanup on error
            if (timer) {
              clearInterval(timer);
              timer = null;
            }
            try { cap.close(); } catch {}
            resolve();
          }
        });
        return { method: 'pcap', events };
      }
    } catch {
      // fall through to netstat polling
    }
  }

  // Fallback: poll netstat for SYN-RECEIVED entries
  // Optimized: reduced polling frequency and added deduplication
  const intervalMs = 1000; // Reduced from 500ms to 1000ms
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

module.exports = { monitorSynAttempts };


