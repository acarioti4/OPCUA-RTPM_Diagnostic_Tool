const net = require('net');

function testPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve({ port, status: 'open', message: 'Connection successful - Port is open and accepting connections' });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, status: 'timeout', message: 'Connection timeout - Port may be filtered or host is unreachable' });
    });

    socket.on('error', (err) => {
      let message = '';
      if (err.code === 'ECONNREFUSED') message = 'Connection refused - Port is closed or service is not running';
      else if (err.code === 'EHOSTUNREACH') message = 'Host unreachable - Check network connectivity';
      else if (err.code === 'ENETUNREACH') message = 'Network unreachable - Check routing or firewall settings';
      else message = `Error: ${err.code || err.message}`;
      resolve({ port, status: 'closed', message, error: err.code });
    });

    socket.connect(port, host);
  });
}

function testPortsConcurrent(host, startPort, endPort, concurrency = 100, onProgress) {
  const totalPorts = endPort - startPort + 1;
  const ports = [];
  for (let p = startPort; p <= endPort; p++) ports.push(p);

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
            onProgress({ current: completed, total: totalPorts, result });
          }
        }).finally(() => {
          inFlight--;
          if (completed === totalPorts) resolve(results);
          else launchMore();
        });
      }
    }
    launchMore();
  });
}

module.exports = { testPort, testPortsConcurrent };


