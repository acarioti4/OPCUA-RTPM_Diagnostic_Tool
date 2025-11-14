// timeout.js
function withTimeout(promise, ms, message = 'Operation timed out') {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), Math.max(1, ms));
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

module.exports = { withTimeout };


