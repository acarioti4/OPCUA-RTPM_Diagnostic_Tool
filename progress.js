// progress.js
function sendProgress(event, payload) {
  try {
    if (event && event.sender) {
      event.sender.send('diagnostics:progress', payload || {});
    }
  } catch {
    // ignore send errors
  }
}

module.exports = { sendProgress };


