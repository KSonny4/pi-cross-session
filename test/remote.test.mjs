// Slice 1 remote peers: config validation, flag-off isolation, gateway
// protocol, and two-machine listing over loopback TLS-PSK.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { loadRemoteConfig, parseHostPort, remoteClientOptions, remoteList, REMOTE_PSK_IDENTITY, validateRemoteConfig } from '../lib/remote.ts';
import { repo, until } from './support/sdk.mjs';

const PSK = 'ab'.repeat(32);
const PORT_A = 17771, PORT_B = 17772, PORT_C = 17773, PORT_GW = 17778, PORT_OFF = 17779;
const SEND_A = 17781, SEND_B = 17782, SEND_OFF = 17784;
const PORT_REAL = 17785, PORT_PXY = 17786, PORT_REJ = 17788;

function validConfig(port = PORT_GW, psk = PSK, peers = []) {
  return { listen: `127.0.0.1:${port}`, psk, peers };
}

test('remote config validation: accepts valid, rejects bad shapes', () => {
  assert.equal(validateRemoteConfig(validConfig()).ok, true);
  assert.equal(validateRemoteConfig(validConfig(PORT_GW, PSK, ['127.0.0.1:17772', '[::1]:17773'])).ok, true);
  for (const [label, config] of [
    ['hostname listen', { ...validConfig(), listen: 'example.com:7717' }],
    ['unspecified listen', { ...validConfig(), listen: '0.0.0.0:7717' }],
    ['unspecified ipv6 listen', { ...validConfig(), listen: '[::0]:7717' }],
    ['unspecified listen [0:0:0:0:0:ffff:0.0.0.0]', { ...validConfig(), listen: '[0:0:0:0:0:ffff:0.0.0.0]:1' }],
    ['unspecified listen [::0:ffff:0.0.0.0]', { ...validConfig(), listen: '[::0:ffff:0.0.0.0]:1' }],
    ['unspecified listen [::%lo0]', { ...validConfig(), listen: '[::%lo0]:1' }],
    ['unspecified listen [::%1]', { ...validConfig(), listen: '[::%1]:1' }],
    ['unspecified listen [::ffff:0:0%lo0]', { ...validConfig(), listen: '[::ffff:0:0%lo0]:1' }],
    ['short psk', { ...validConfig(), psk: 'abc' }],
    ['uppercase psk', { ...validConfig(), psk: 'AB'.repeat(32) }],
    ['hostname peer', { ...validConfig(), peers: ['peer.local:7717'] }],
    ['non-array peers', { ...validConfig(), peers: '127.0.0.1:7717' }],
    ['non-object', ['127.0.0.1:7717']],
  ]) {
    const result = validateRemoteConfig(config);
    assert.equal(result.ok, false, label);
  }
  assert.equal(parseHostPort('[::1]:7717')?.host, '::1');
  assert.equal(parseHostPort('example.com:7717'), null);
  assert.equal(parseHostPort('127.0.0.1:0'), null);
});

test('remote config file: rejects bad mode / symlink / oversize / bad json; accepts valid', async () => {
  const root = process.env.PI_CROSS_TEST_PRIVATE_ROOT;
  async function dir(name) {
    const dir = path.join(root, `remote-cfg-${name}`);
    await fs.promises.rm(dir, { recursive: true, force: true });
    await fs.promises.mkdir(dir, { recursive: true });
    return dir;
  }
  async function write(dir, content, mode = 0o600) {
    const file = path.join(dir, 'cross-session-remote.json');
    await fs.promises.writeFile(file, typeof content === 'string' ? content : JSON.stringify(content), { mode });
    return file;
  }
  const good = await dir('good');
  await write(good, validConfig());
  assert.equal((await loadRemoteConfig(good)).status, 'ok');

  const missing = await dir('missing');
  assert.equal((await loadRemoteConfig(missing)).status, 'absent');

  const mode = await dir('mode');
  await write(mode, validConfig());
  await fs.promises.chmod(path.join(mode, 'cross-session-remote.json'), 0o644);
  assert.match((await loadRemoteConfig(mode)).error, /0600/);

  const link = await dir('link');
  const target = await write(link, validConfig());
  await fs.promises.rename(target, target + '.real');
  fs.symlinkSync(target + '.real', target);
  assert.match((await loadRemoteConfig(link)).error, /symlink/);

  const big = await dir('big');
  await write(big, 'x'.repeat(65 * 1024));
  assert.match((await loadRemoteConfig(big)).error, /64 KiB/);

  const json = await dir('json');
  await write(json, '{not json');
  assert.match((await loadRemoteConfig(json)).error, /JSON/);

  const shape = await dir('shape');
  await write(shape, { ...validConfig(), listen: 'peer.local:7717' });
  assert.match((await loadRemoteConfig(shape)).error, /listen/);
});

async function expectRefused(port) {
  await assert.rejects(new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.on('error', (error) => { socket.destroy(); reject(error); });
    socket.on('connect', () => { socket.destroy(); reject(new Error(`unexpected TCP listener on ${port}`)); });
    setTimeout(() => resolve(), 1000);
  }), /ECONNREFUSED/);
}

async function writeSharedConfig(config) {
  const file = path.join(process.env.PI_CODING_AGENT_DIR, 'cross-session-remote.json');
  await fs.promises.writeFile(file, JSON.stringify(config), { mode: 0o600 });
  return file;
}

test('flag off: valid config present but no TCP listener and no listing change', async () => {
  const { component } = await import('./support/component.mjs');
  const file = await writeSharedConfig(validConfig(PORT_OFF));
  const a = await component('plain');
  try {
    await expectRefused(PORT_OFF);
    const result = await a.tool('list_pi', {});
    assert.deepEqual(Object.keys(result.details).sort(), ['peers', 'self']);
    assert.ok(!result.content[0].text.includes('— remote '), result.content[0].text);
  } finally {
    await a.close();
    await fs.promises.rm(file, { force: true });
  }
});

async function rawFirstFrame(port, psk, payload) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1', port, ...remoteClientOptions(),
      pskCallback: () => ({ psk: Buffer.from(psk, 'hex'), identity: REMOTE_PSK_IDENTITY }),
    });
    let buffer = '';
    socket.setEncoding('utf8');
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('TIMEOUT raw frame')); }, 5000);
    socket.on('secureConnect', () => socket.write(typeof payload === 'string' ? payload : `${JSON.stringify(payload)}\n`));
    socket.on('data', (data) => { buffer += data; });
    socket.on('error', (error) => { clearTimeout(timer); reject(error); });
    socket.on('close', () => { clearTimeout(timer); resolve(buffer.trim()); });
  });
}

test('gateway: remote-list serves local peers without secrets; other first frames fail closed', { timeout: 30000 }, async () => {
  const { component } = await import('./support/component.mjs');
  const file = await writeSharedConfig(validConfig(PORT_GW));
  const flagOn = (_ctx, _bus, runtime) => runtime.flagValues.set('cross-session-remote', true);
  const a = await component('gw-a', { configure: flagOn });
  const b = await component('gw-b', { configure: flagOn }); // EADDRINUSE: silently not the gateway
  try {
    // Gateway serves itself even with no other local sessions.
    await until(async () => (await remoteList('127.0.0.1', PORT_GW, PSK, 2000)).length === 2, 'all local peers listed');
    const listed = await remoteList('127.0.0.1', PORT_GW, PSK, 2000);
    assert.deepEqual(new Set(listed.map((peer) => peer.instanceId)), new Set([a.peer.instanceId, b.peer.instanceId]));
    assert.ok(listed.every((peer) => !('token' in peer) && !('socketPath' in peer)));
    assert.ok(listed.every((peer) => typeof peer.ref === 'string' && /^[0-9a-f]{6,32}$/.test(peer.ref)));
    assert.ok(b.notices.every((args) => !/remote|EADDRINUSE/i.test(JSON.stringify(args))), JSON.stringify(b.notices));
    const helloReply = JSON.parse(await rawFirstFrame(PORT_GW, PSK, { v: 1, type: 'hello', requestId: 'abcdefgh', token: 'x' }));
    assert.equal(helloReply.ok, false);
    assert.equal(helloReply.requestId, 'abcdefgh');
    assert.equal(await rawFirstFrame(PORT_GW, PSK, 'not json\n'), '');
  } finally {
    await b.close();
    await a.close();
    await fs.promises.rm(file, { force: true });
  }
});

function spawnWorker(name, port, peerPorts, psk) {
  const child = spawn(process.execPath, [path.join(repo, 'test/support/remote-worker.mjs'), name, String(port)], {
    cwd: process.env.PI_CROSS_TEST_PRIVATE_ROOT,
    env: {
      ...process.env,
      PI_CROSS_TEST_REMOTE_PSK: psk,
      PI_CROSS_TEST_REMOTE_PEERS: JSON.stringify(peerPorts.map((peer) => `127.0.0.1:${peer}`)),
    },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  const messages = [];
  let error = '';
  child.on('message', (message) => messages.push(message));
  child.stderr.on('data', (data) => { error += data; });
  const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  return {
    child, messages, exited, name,
    async wait(type, ms = 15000) {
      await until(() => messages.some((m) => m.type === type || m.type === 'failure') || child.exitCode !== null, `${name}:${type}`, ms);
      const failure = messages.find((m) => m.type === 'failure');
      assert.ok(!failure, failure?.error ?? error);
      const result = messages.find((m) => m.type === type);
      assert.ok(result, error);
      return result;
    },
  };
}

test('two machines: matching psk lists remote sessions with machine; wrong psk is a diagnostic, not a crash', { timeout: 60000 }, async () => {
  const psk = randomBytes(32).toString('hex');
  const A = spawnWorker('A', PORT_A, [PORT_B, PORT_C], psk);
  const B = spawnWorker('B', PORT_B, [PORT_A], psk);
  const C = spawnWorker('C', PORT_C, [PORT_A], 'cd'.repeat(32));
  const workers = [A, B, C];
  try {
    const [, readyB] = await Promise.all([A.wait('ready', 30000), B.wait('ready', 30000), C.wait('ready', 30000)]);
    A.child.send({ type: 'list' });
    const listedA = await A.wait('listed');
    const remoteA = listedA.details.peers.filter((peer) => peer.machine);
    assert.equal(remoteA.length, 1);
    assert.equal(remoteA[0].instanceId, readyB.peer.instanceId);
    assert.equal(remoteA[0].machine, `127.0.0.1:${PORT_B}`);
    assert.ok(!('token' in remoteA[0]) && !('socketPath' in remoteA[0]));
    assert.match(listedA.text, new RegExp(`— remote 127\\.0\\.0\\.1:${PORT_B}`));
    assert.ok(!new RegExp(`— remote 127\\.0\\.0\\.1:${PORT_C}`).test(listedA.text), listedA.text);
    assert.equal(listedA.details.remoteDiagnostics.length, 1);
    assert.match(listedA.details.remoteDiagnostics[0], new RegExp(`127\\.0\\.0\\.1:${PORT_C}`));
    B.child.send({ type: 'list' });
    const listedB = await B.wait('listed');
    assert.equal(listedB.details.peers.filter((peer) => peer.machine).length, 1);
    assert.equal(listedB.details.remoteDiagnostics.length, 0);
    console.log(JSON.stringify({ evidence: 'two machines/loopback TLS-PSK remote-list', remote: 1, diagnostics: 1 }));
  } finally {
    for (const x of workers) {
      if (x.child.exitCode === null) {
        x.child.send({ type: 'close' });
        await Promise.race([x.exited, until(() => x.child.exitCode !== null, 'worker exit', 10000)]);
      }
      if (x.child.exitCode === null) { x.child.kill('SIGKILL'); await x.exited; }
      const agentDir = path.join(process.env.PI_CROSS_TEST_PRIVATE_ROOT, `remote-${x.name}-${x.child.pid}`);
      try { fs.rmdirSync(`/tmp/pi-peers-${process.getuid()}-${createHash('sha256').update(agentDir).digest('hex').slice(0, 12)}`); } catch { /* best effort */ }
    }
  }
});

async function closeWorkers(workers) {
  for (const x of workers) {
    if (x.child.exitCode === null) {
      x.child.send({ type: 'close' });
      await Promise.race([x.exited, until(() => x.child.exitCode !== null, 'worker exit', 10000)]);
    }
    if (x.child.exitCode === null) { x.child.kill('SIGKILL'); await x.exited; }
    const agentDir = path.join(process.env.PI_CROSS_TEST_PRIVATE_ROOT, `remote-${x.name}-${x.child.pid}`);
    try { fs.rmdirSync(`/tmp/pi-peers-${process.getuid()}-${createHash('sha256').update(agentDir).digest('hex').slice(0, 12)}`); } catch { /* best effort */ }
  }
}

async function remoteSend(worker, target, message, goalId) {
  const id = `${Date.now()}-${Math.random()}`;
  worker.child.send({ type: 'send', id, target, message, ...(goalId ? { goalId } : {}) });
  await until(() => worker.messages.some(m => (m.type === 'sent' || m.type === 'sendFailed') && m.id === id), 'send result', 15000);
  const result = worker.messages.find(m => (m.type === 'sent' || m.type === 'sendFailed') && m.id === id);
  assert.ok(result);
  return result;
}

async function pollReceived(worker, predicate, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const id = `poll-${Date.now()}-${Math.random()}`;
    worker.child.send({ type: 'received', id });
    await until(() => worker.messages.some(m => m.type === 'received' && m.id === id), 'received poll', 5000);
    const reply = worker.messages.find(m => m.type === 'received' && m.id === id);
    if (reply && predicate(reply.messages)) return reply;
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('TIMEOUT waiting for remote delivery');
}

test('remote send delivers both ways with remote marker', { timeout: 90000 }, async () => {
  const psk = randomBytes(32).toString('hex');
  const A = spawnWorker('SA', SEND_A, [SEND_B], psk);
  const B = spawnWorker('SB', SEND_B, [SEND_A], psk);
  try {
    const [readyA, readyB] = await Promise.all([A.wait('ready', 30000), B.wait('ready', 30000)]);
    const textAB = `hello-remote-${Date.now()}`;
    const sentAB = await remoteSend(A, readyB.peer.instanceId, textAB);
    assert.equal(sentAB.type, 'sent');
    assert.ok(['submitted', 'queued'].includes(sentAB.status), JSON.stringify(sentAB));
    const gotB = await pollReceived(B, msgs => msgs.some(m => m.text === textAB));
    const msgB = gotB.messages.find(m => m.text === textAB);
    assert.ok(msgB.content.includes('remote 127.0.0.1'), msgB.content);
    assert.equal(msgB.remoteMachine, '127.0.0.1');
    const textBA = `reply-remote-${Date.now()}`;
    const sentBA = await remoteSend(B, readyA.peer.instanceId, textBA);
    assert.equal(sentBA.type, 'sent');
    assert.ok(['submitted', 'queued'].includes(sentBA.status));
    const gotA = await pollReceived(A, msgs => msgs.some(m => m.text === textBA));
    assert.ok(gotA.messages.find(m => m.text === textBA).content.includes('remote 127.0.0.1'));
    console.log(JSON.stringify({ evidence: 'remote send both ways via gateway relay', off: 'no listener, on works' }));
  } finally { await closeWorkers([A, B]); }
});

test('remote rejects: wrong psk, goal scope, spoofed local identity, unknown target', { timeout: 90000 }, async () => {
  const psk = randomBytes(32).toString('hex');
  const A = spawnWorker('RA', SEND_A, [SEND_B], psk);
  const B = spawnWorker('RB', SEND_B, [SEND_A], psk);
  try {
    const [readyA, readyB] = await Promise.all([A.wait('ready', 30000), B.wait('ready', 30000)]);
    await assert.rejects(rawFirstFrame(SEND_B, 'cd'.repeat(32), { v: 1, type: 'remote-list', requestId: 'a1b2c3d4' }));
    const goalRes = await remoteSend(A, readyB.peer.instanceId, 'goal-text', 'goal123');
    assert.equal(goalRes.type, 'sendFailed');
    assert.match(goalRes.error, /unsupported/);
    assert.match(goalRes.error, /remote senders cannot use goal scope or bridges yet/);
    const spoof = JSON.parse(await rawFirstFrame(SEND_B, psk, { v: 1, type: 'hello', requestId: 'd4e5f6a7', token: '', target: { id: readyB.peer.id, instanceId: readyB.peer.instanceId }, capabilities: ['cancel-safe-queue-v1'], from: { id: 'spoof', instanceId: readyB.peer.instanceId, name: 'spoof', remote: true } }));
    assert.equal(spoof.ok, false);
    assert.equal(spoof.status, 'authentication_failed');
    const unknownId = '00'.repeat(16);
    const missing = JSON.parse(await rawFirstFrame(SEND_B, psk, { v: 1, type: 'hello', requestId: 'e5f6a7b8', token: '', target: { id: 'x', instanceId: unknownId }, from: { id: 'r', instanceId: readyA.peer.instanceId, name: 'r', remote: true } }));
    assert.equal(missing.ok, false);
    assert.equal(missing.status, 'not_found');
  } finally { await closeWorkers([A, B]); }
});

test('stray machine key in a local registration never renders as remote', { timeout: 30000 }, async () => {
  const { component } = await import('./support/component.mjs');
  const a = await component('stray-a');
  const b = await component('stray-b');
  const c = await component('stray-b');
  try {
    const file = path.join(process.env.PI_CODING_AGENT_DIR, 'peers', `${b.peer.instanceId}.json`);
    const reg = JSON.parse(await fs.promises.readFile(file, 'utf8'));
    await fs.promises.writeFile(file, JSON.stringify({ ...reg, machine: '10.0.0.9:7717' }));
    const sent = await a.tool('send_pi_message', { target: b.peer.instanceId, message: 'local hello' });
    const detailsJson = JSON.stringify(sent.details);
    assert.ok(!/[0-9a-f]{64}/.test(detailsJson), detailsJson);
    assert.ok(!detailsJson.includes('remote'), detailsJson);
    assert.ok(!('token' in sent.details.target) && !('machine' in sent.details.target), detailsJson);
    await until(() => b.calls.some(call => call.message.details?.text === 'local hello'), 'local delivery');
    const got = b.calls.find(call => call.message.details?.text === 'local hello');
    assert.equal(got.message.details.remoteMachine, undefined);
    assert.ok(!String(got.message.content).includes('remote'), String(got.message.content));
    let ambiguous;
    try { await a.tool('send_pi_message', { target: 'stray-b', message: 'hi' }); assert.fail('expected ambiguous'); }
    catch (error) { ambiguous = error; }
    assert.match(ambiguous.message, /Ambiguous session/);
    assert.ok(!ambiguous.message.includes('remote'), ambiguous.message);
    assert.ok(!/[0-9a-f]{64}/.test(JSON.stringify(ambiguous.target)), JSON.stringify(ambiguous.target));
  } finally {
    await c.close();
    await b.close();
    await a.close();
  }
});

test('gateway relay rejects a remote claim of another local session', { timeout: 30000 }, async () => {
  const { component } = await import('./support/component.mjs');
  const file = await writeSharedConfig(validConfig(PORT_REJ));
  const flagOn = (_ctx, _bus, runtime) => runtime.flagValues.set('cross-session-remote', true);
  const ga = await component('rej-a', { configure: flagOn });
  const gb = await component('rej-b', { configure: flagOn });
  try {
    await until(async () => (await remoteList('127.0.0.1', PORT_REJ, PSK, 2000)).length === 2, 'gateway up');
    // from.instanceId is another live LOCAL session: readPeer rejects the claim.
    const spoof = JSON.parse(await rawFirstFrame(PORT_REJ, PSK, { v: 1, type: 'hello', requestId: 'b1c2d3e4', token: '', target: { id: gb.peer.id, instanceId: gb.peer.instanceId }, capabilities: ['cancel-safe-queue-v1'], from: { id: ga.peer.id, instanceId: ga.peer.instanceId, name: 'spoof', remote: true } }));
    assert.equal(spoof.ok, false);
    assert.equal(spoof.status, 'authentication_failed');
  } finally {
    await gb.close();
    await ga.close();
    await fs.promises.rm(file, { force: true });
  }
});

test('flag off: real remote target not_found with no connection; remote hello to unix socket rejected', { timeout: 60000 }, async () => {
  const { component, wire } = await import('./support/component.mjs');
  const { randomUUID } = await import('node:crypto');
  // Real session behind a real gateway; the sender keeps the flag off.
  // Counting TCP proxy in front of the gateway: a TLS handshake cannot start
  // without a TCP connect, so zero connects proves no attempt was made.
  const psk = randomBytes(32).toString('hex');
  const B = spawnWorker('GO', PORT_REAL, [], psk);
  let connects = 0;
  const proxy = net.createServer(client => {
    connects++;
    const upstream = net.createConnection({ host: '127.0.0.1', port: PORT_REAL });
    client.pipe(upstream); upstream.pipe(client);
    client.on('error', () => upstream.destroy());
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
  });
  await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen({ host: '127.0.0.1', port: PORT_PXY }, resolve); });
  const file = await writeSharedConfig({ listen: `127.0.0.1:${SEND_OFF}`, psk, peers: [`127.0.0.1:${PORT_PXY}`] });
  const readyB = await B.wait('ready', 30000);
  const a = await component('off-sender');
  try {
    await expectRefused(SEND_OFF);
    await assert.rejects(a.tool('send_pi_message', { target: readyB.peer.instanceId, message: 'hi' }), /not_found/);
    assert.equal(connects, 0);
    // The counter is live: a real remote-list through the proxy connects once.
    assert.equal((await remoteList('127.0.0.1', PORT_PXY, psk, 2000)).length, 1);
    assert.equal(connects, 1);
  } finally {
    await a.close();
    await fs.promises.rm(file, { force: true });
    await new Promise(resolve => proxy.close(resolve));
    await closeWorkers([B]);
  }
  const off = await component('off-receiver2');
  try {
    const hello = { v: 1, type: 'hello', requestId: randomUUID(), token: off.peer.token, target: { id: off.peer.id, instanceId: off.peer.instanceId }, capabilities: ['cancel-safe-queue-v1'], from: { id: 'r', instanceId: randomBytes(16).toString('hex'), name: 'remote-guy', remote: true, machine: '127.0.0.1' } };
    const reply = await wire(null, off, null, { hello });
    assert.equal(reply.ok, false);
    assert.equal(reply.status, 'authentication_failed');
    // A local-form hello (valid token) with a stray remote key is still local, as before slice 2.
    const local = { ...hello, requestId: randomUUID(), from: { id: off.peer.id, instanceId: off.peer.instanceId, token: off.peer.token, remote: true } };
    assert.equal((await wire(null, off, null, { hello: local })).ok, true);
  } finally { await off.close(); }
});
