/**
 * Hunt Command Renderer Content-Security-Policy Constants (`#178` G1.2, `#189`).
 *
 * Packaged CSP enforces `connect-src 'none'` (all daemon & telemetry traffic traverses allowlisted
 * Electron preload IPC) and `worker-src 'self' blob:` (permitting Sigma.js v3 WebGL workers).
 */
export const PACKAGED_RENDERER_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'none'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'";

export const DEV_SERVE_RENDERER_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws://127.0.0.1:* http://127.0.0.1:* ws://localhost:* http://localhost:*; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'";
