// Flagged TLS-PSK remote gateway helpers (slice 1: remote-list only).
// Pure transport/config code; extension wiring lives in extensions/cross-session.ts.
import { randomUUID } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";
import {
  connect,
  type ConnectionOptions,
  type TLSSocket,
  type TlsOptions,
} from "node:tls";
import { TextDecoder } from "node:util";

export const REMOTE_CONFIG_FILENAME = "cross-session-remote.json";
export const REMOTE_MAX_CONFIG_BYTES = 64 * 1024;
export const REMOTE_MAX_FRAME_BYTES = 1_048_576; // Mirrors the local wire frame cap.
export const REMOTE_MAX_PEERS = 64;
export const REMOTE_PSK_IDENTITY = "pi-cross-session";
// Node's pskCallback does not do TLS 1.3 PSK, so pin TLS 1.2 with PSK ciphers.
export const REMOTE_CIPHERS = "ECDHE-PSK-CHACHA20-POLY1305:PSK-AES256-GCM-SHA384";

export type RemoteEndpoint = { host: string; port: number };
export type RemoteConfig = { listen: RemoteEndpoint; peers: RemoteEndpoint[]; psk: string };
export type RemoteListedPeer = {
  id: string;
  instanceId: string;
  name: string;
  status: string;
  cwd: string;
  ref: string;
};

// IP literals only (IPv4, or IPv6 as [addr]:port). No hostnames: there is no
// DNS in the trust path. Never 0.0.0.0/::: bind exactly the configured address.
export function parseHostPort(value: unknown): RemoteEndpoint | null {
  if (typeof value !== "string") return null;
  let host = "";
  let portText = "";
  const bracketed = /^\[([^\]]+)\]:(\d{1,5})$/.exec(value);
  if (bracketed) {
    host = bracketed[1];
    portText = bracketed[2];
  } else {
    const colon = value.lastIndexOf(":");
    if (colon < 0) return null;
    host = value.slice(0, colon);
    portText = value.slice(colon + 1);
    // A bare colon means IPv6 without brackets, or a malformed entry.
    if (host.includes(":") || !/^\d{1,5}$/.test(portText)) return null;
  }
  const family = isIP(host);
  if (family !== 4 && family !== 6) return null;
  if (host === "0.0.0.0" || host === "::") return null;
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

export function formatEndpoint(endpoint: RemoteEndpoint): string {
  return endpoint.host.includes(":")
    ? `[${endpoint.host}]:${endpoint.port}`
    : `${endpoint.host}:${endpoint.port}`;
}

export type RemoteConfigValidation =
  | { ok: true; config: RemoteConfig }
  | { ok: false; error: string };

export function validateRemoteConfig(value: unknown): RemoteConfigValidation {
  const invalid = (error: string): RemoteConfigValidation => ({ ok: false, error });
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return invalid("remote config must be a JSON object");
  }
  const raw = value as Record<string, unknown>;
  const listen = parseHostPort(raw.listen);
  if (!listen) {
    return invalid("remote config 'listen' must be an IP-literal host:port (IPv6 as [addr]:port), never a hostname or 0.0.0.0/::");
  }
  if (typeof raw.psk !== "string" || !/^[0-9a-f]{64}$/.test(raw.psk)) {
    return invalid("remote config 'psk' must be 64 lowercase hex characters (generate with: openssl rand -hex 32)");
  }
  const peersRaw = raw.peers ?? [];
  if (!Array.isArray(peersRaw)) return invalid("remote config 'peers' must be an array of IP-literal host:port endpoints");
  if (peersRaw.length > REMOTE_MAX_PEERS) {
    return invalid(`remote config 'peers' lists more than ${REMOTE_MAX_PEERS} endpoints`);
  }
  const peers: RemoteEndpoint[] = [];
  for (const entry of peersRaw) {
    const parsed = parseHostPort(entry);
    if (!parsed) return invalid(`remote config peer ${JSON.stringify(entry)} is not an IP-literal host:port`);
    peers.push(parsed);
  }
  return { ok: true, config: { listen, peers, psk: raw.psk } };
}

export type RemoteConfigLoad =
  | { status: "absent" }
  | { status: "ok"; config: RemoteConfig }
  | { status: "error"; error: string };

export async function loadRemoteConfig(agentDir: string): Promise<RemoteConfigLoad> {
  const path = join(agentDir, REMOTE_CONFIG_FILENAME);
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? { status: "absent" }
      : { status: "error", error: `cannot stat ${REMOTE_CONFIG_FILENAME}: ${(error as Error).message}` };
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    return { status: "error", error: `${REMOTE_CONFIG_FILENAME} must be a regular file, not a symlink` };
  }
  if (info.size > REMOTE_MAX_CONFIG_BYTES) {
    return { status: "error", error: `${REMOTE_CONFIG_FILENAME} exceeds 64 KiB` };
  }
  if (process.platform !== "win32") {
    const uid = process.getuid?.();
    if (uid !== undefined && info.uid !== uid) {
      return { status: "error", error: `${REMOTE_CONFIG_FILENAME} is owned by uid ${info.uid}, expected ${uid}` };
    }
    if ((info.mode & 0o777) !== 0o600) {
      return { status: "error", error: `${REMOTE_CONFIG_FILENAME} must have mode 0600` };
    }
  }
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    return { status: "error", error: `cannot read ${REMOTE_CONFIG_FILENAME}: ${(error as Error).message}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { status: "error", error: `${REMOTE_CONFIG_FILENAME} is not valid JSON` };
  }
  const validated = validateRemoteConfig(parsed);
  return validated.ok
    ? { status: "ok", config: validated.config }
    : { status: "error", error: validated.error };
}

export function gatewayServerOptions(psk: string): TlsOptions {
  const key = Buffer.from(psk, "hex");
  return {
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
    ciphers: REMOTE_CIPHERS,
    pskCallback: (_socket, identity) =>
      String(identity ?? "") === REMOTE_PSK_IDENTITY ? key : null,
  };
}

export function remoteClientOptions(): ConnectionOptions {
  // The key is supplied per connection: see remoteList.
  return {
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
    ciphers: REMOTE_CIPHERS,
    checkServerIdentity: () => undefined, // PSK authenticates the server.
  };
}

function isRemoteListedPeer(value: unknown): value is RemoteListedPeer {
  if (!value || typeof value !== "object") return false;
  const peer = value as Record<string, unknown>;
  return (
    typeof peer.id === "string" && peer.id.length > 0 && peer.id.length <= 512 &&
    typeof peer.instanceId === "string" && /^[0-9a-f]{32}$/.test(peer.instanceId) &&
    typeof peer.name === "string" && peer.name.length > 0 &&
    (peer.status === "idle" || peer.status === "busy") &&
    typeof peer.cwd === "string" &&
    typeof peer.ref === "string" && peer.ref.length > 0
  );
}

// Query one peer gateway for its live local sessions. Throws on any transport,
// handshake, timeout, or protocol failure; callers turn that into a diagnostic.
export async function remoteList(
  host: string,
  port: number,
  psk: string,
  timeoutMs: number,
): Promise<RemoteListedPeer[]> {
  const requestId = randomUUID();
  const line = `${JSON.stringify({ v: 1, type: "remote-list", requestId })}\n`;
  const label = formatEndpoint({ host, port });
  return new Promise<RemoteListedPeer[]>((resolve, reject) => {
    let settled = false;
    let socket: TLSSocket | undefined;
    const fail = (code: string, detail: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      reject(new Error(`${code}: ${detail}`));
    };
    const timer = setTimeout(
      () => fail("timeout", `no remote-list response from ${label} within ${timeoutMs}ms`),
      Math.max(1, timeoutMs),
    );
    timer.unref();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let text = "";
    let bytes = 0;
    socket = connect({
      host,
      port,
      ...remoteClientOptions(),
      pskCallback: () => ({ psk: Buffer.from(psk, "hex"), identity: REMOTE_PSK_IDENTITY }),
    });
    socket.on("secureConnect", () => {
      if (!settled) socket?.write(line);
    });
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > REMOTE_MAX_FRAME_BYTES) {
        fail("message_too_large", `remote-list response from ${label} exceeds frame cap`);
        return;
      }
      try {
        text += decoder.decode(chunk, { stream: true });
      } catch {
        fail("invalid_frame", `remote-list response from ${label} is not valid UTF-8`);
        return;
      }
      const newline = text.indexOf("\n");
      if (newline < 0) return;
      let value: unknown;
      try {
        value = JSON.parse(text.slice(0, newline));
      } catch {
        fail("invalid_response", `remote-list response from ${label} is not JSON`);
        return;
      }
      const frame = value as {
        v?: unknown; type?: unknown; requestId?: unknown;
        ok?: unknown; status?: unknown; error?: unknown; peers?: unknown;
      } | null;
      if (!frame || frame.v !== 1 || frame.type !== "response" || frame.requestId !== requestId) {
        fail("invalid_response", `remote-list response from ${label} does not match this request`);
        return;
      }
      if (frame.ok !== true) {
        fail(String(frame.status ?? "refused"), String(typeof frame.error === "string" ? frame.error : `gateway refused remote-list (${label})`));
        return;
      }
      if (frame.status !== "listed" || !Array.isArray(frame.peers)) {
        fail("invalid_response", `remote-list response from ${label} is not a listing`);
        return;
      }
      const peers = frame.peers.filter(isRemoteListedPeer);
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      resolve(peers);
    });
    socket.on("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code ?? "transport_error";
      fail(code, `${label}: ${error.message}`);
    });
    socket.on("close", () => {
      if (!settled) fail("connection_closed", `${label} closed before answering remote-list`);
    });
  });
}
