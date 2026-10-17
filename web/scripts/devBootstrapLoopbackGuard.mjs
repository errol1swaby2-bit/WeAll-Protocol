// Development-only defense in depth for the local controlled-devnet key handoff.
// Do not treat loopback filtering as authorization for production credentials.
import { isIP } from "node:net";

export function isLoopbackPeer(input) {
  const value = String(input || "").trim().toLowerCase();
  if (value === "::1") return true;
  if (value.startsWith("::ffff:")) return isLoopbackPeer(value.slice(7));
  if (isIP(value) !== 4) return false;
  return value.split(".")[0] === "127";
}

function localHostHeader(input) {
  const value = String(input || "").trim();
  if (!value || /[/\\@?#\s]/.test(value)) return null;
  try {
    const parsed = new URL("http://" + value);
    if (parsed.username || parsed.password || parsed.pathname !== "/") return null;
    if (!["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname.toLowerCase())) return null;
    return parsed.host.toLowerCase();
  } catch {
    return null;
  }
}

export function permitsLocalSecretRequest({ remoteAddress, host, origin, fetchSite } = {}) {
  const localHost = localHostHeader(host);
  if (!isLoopbackPeer(remoteAddress) || !localHost) return false;

  // An unrelated browser origin must not use a cross-origin local-network
  // fetch to obtain keys, even if CORS settings change in the future.
  if (fetchSite && !["same-origin", "none"].includes(String(fetchSite).toLowerCase())) return false;
  if (origin) {
    try {
      const originUrl = new URL(String(origin));
      if (originUrl.protocol !== "http:" || originUrl.host.toLowerCase() !== localHost) return false;
    } catch {
      return false;
    }
  }
  return true;
}

function isDevRoute(url) {
  let path;
  try {
    path = new URL(String(url || "/"), "http://localhost").pathname;
    // Decode nested escaped segments before applying the protection.
    for (let i = 0; i < 3; i++) {
      const decoded = decodeURIComponent(path);
      if (decoded === path) break;
      path = decoded;
    }
  } catch {
    // Fail closed for malformed possible /v1 requests.
    return String(url || "").toLowerCase().startsWith("/v1");
  }
  return /^\/v1\/dev(?:\/|$)/i.test(path);
}

export function protectDevBootstrapSecrets(req, res, next) {
  if (!isDevRoute(req.url)) return next();
  if (permitsLocalSecretRequest({
    remoteAddress: req.socket?.remoteAddress,
    host: req.headers?.host,
    origin: req.headers?.origin,
    fetchSite: req.headers?.["sec-fetch-site"],
  })) return next();

  res.statusCode = 403;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify({ detail: "local_dev_bootstrap_only" }));
}
