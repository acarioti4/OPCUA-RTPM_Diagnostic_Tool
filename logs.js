const { app } = require('electron');
const path = require('path');
const fs = require('fs');

function ensureLogDir() {
  const logDir = path.join(app.getPath('userData'), 'logs');
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  return logDir;
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

module.exports = {
  ensureLogDir,
  generateLogContent
};


