function createHelloBuffer(endpointUrl) {
  const endpointBytes = Buffer.from(endpointUrl, 'utf8');
  const stringLen = Buffer.alloc(4);
  stringLen.writeInt32LE(endpointBytes.length, 0);

  const body = Buffer.alloc(20);
  body.writeUInt32LE(0, 0);
  body.writeUInt32LE(16384, 4);
  body.writeUInt32LE(16384, 8);
  body.writeUInt32LE(0, 12);
  body.writeUInt32LE(0, 16);

  const header = Buffer.alloc(8);
  header.write('HELF', 0, 'ascii');
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

module.exports = { createHelloBuffer, parseAckHeader };


