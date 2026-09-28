import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { createHash } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
const deny = () => { throw new Error('TEST_NETWORK_DENIED'); };
globalThis.fetch = deny;
for (const mod of [http, https]) for (const key of ['request', 'get']) mod[key] = deny;
const dnsLookupOrig = dns.lookup;
for (const mod of [dns, dns.promises, dns.Resolver.prototype, dns.promises.Resolver.prototype]) {
  for (const key of Object.getOwnPropertyNames(mod)) if (/^(lookup|resolve|reverse|setServers)/.test(key)) mod[key] = deny;
}
// Node resolves even literal-IP listen/connect hosts via dns.lookup (no packets
// leave the machine for numeric addresses); let those through, deny real DNS.
dns.lookup = (host, ...rest) => (typeof host === 'string' && net.isIP(host) ? dnsLookupOrig(host, ...rest) : deny());
function allowed(file) {
  const root = process.env.PI_CROSS_TEST_PRIVATE_ROOT;
  const agent = process.env.PI_CODING_AGENT_DIR;
  if (!root || !path.basename(root).startsWith('pcs-test-') || !agent?.startsWith(root + '/')) return false;
  const runtime = `/tmp/pi-peers-${process.getuid?.() ?? 0}-${createHash('sha256').update(agent).digest('hex').slice(0, 12)}`;
  const inside = p => [root, runtime, path.join(fs.realpathSync('/tmp'), path.basename(runtime))].some(r => p.startsWith(r + '/'));
  if (typeof file !== 'string' || !inside(path.resolve(file))) return false;
  try { return inside(fs.realpathSync(file)); } catch (e) { return e.code === 'ENOENT'; }
}
for (const [proto, key] of [[net.Socket.prototype, 'connect'], [net.Server.prototype, 'listen']]) {
  const original = proto[key];
  proto[key] = function (...args) {
    let opts = args[0]; if (Array.isArray(opts)) opts = opts[0];
    if (loopbackTcp(opts, args.slice(1))) return original.apply(this, args);
    if (!allowed(typeof opts === 'string' ? opts : opts?.path)) return deny();
    return original.apply(this, args);
  };
}
// Remote-gateway tests only: allow TCP listen/connect on 127.0.0.1/::1.
// No hostnames, no other addresses; DNS/fetch/http denial above is untouched.
function loopbackTcp(opts, rest) {
  let host, port;
  if (typeof opts === 'number') { port = opts; host = typeof rest[0] === 'string' ? rest[0] : undefined; }
  else if (opts && typeof opts === 'object') { port = opts.port; host = opts.host ?? opts.hostname; }
  else return false;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  return host === '127.0.0.1' || host === '::1';
}
syncBuiltinESMExports();
