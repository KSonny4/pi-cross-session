import test from 'node:test';
import assert from 'node:assert/strict';
import { component, wire, message, info } from './support/component.mjs';
import { createRequire } from 'node:module';
const { createJiti } = createRequire(import.meta.resolve('@earendil-works/pi-coding-agent'))('jiti');
const { PeerGoals, GOAL_ENTRY } = await createJiti(import.meta.url).import('../lib/peer-goal.ts');
const gate = (x, toolName = 'mesh', input = { action: 'run' }) => x.emit('tool_call', { toolName, input, toolCallId: 'in-flight' });
async function notification(x, id) {
  x.setIdle(false); x.controller = new AbortController(); x.ctx.signal = x.controller.signal;
  await x.emit('agent_start');
  await x.emit('message_start', { message: { role: 'custom', customType: 'subagent-notification', details: { ids: [id] } } });
}

for (const revoke of ['abort', 'complete', 'reload']) test(`late result after ${revoke} retains revoked goal ownership across a new goal`, async () => {
  const x = await component('late-' + revoke);
  try {
    await x.busy();
    const { goalId } = (await x.tool('peer_goal', { action: 'start', objective: 'Original task' })).details;
    assert.equal(await gate(x), undefined);
    if (revoke === 'abort') { x.controller.abort(); await x.settled(false); }
    if (revoke === 'complete') { await x.tool('peer_goal', { action: 'complete', goalId }); await x.settled(); }
    if (revoke === 'reload') { await x.settled(); await x.emit('session_start'); }
    // The old operation finished even though its authorization has already ended.
    await x.emit('tool_result', { toolName: 'mesh', toolCallId: 'in-flight', details: { run: { id: 'late-run' } }, isError: false });
    await x.busy(); await x.tool('peer_goal', { action: 'start', objective: 'New unrelated task' }); await x.settled();
    await notification(x, 'mesh:late-run:1:1');
    for (const [name, input] of [['mesh', { action: 'run' }], ['set_config', {}], ['peer_goal', { action: 'bind', goalId }]]) assert.equal((await gate(x, name, input))?.block, true);
    await x.settled();
    // Truly unscoped notifications keep the established behavior.
    await notification(x, 'mesh:unscoped-run:1:1'); assert.equal(await gate(x), undefined); await x.settled();
  } finally { await x.close(); }
});

test('fresh extension instance recovers only ownership evidence, never grants, from the SDK journal', () => {
  const entries = [], append = data => entries.push({ type: 'custom', customType: GOAL_ENTRY, data });
  const scope = { sessionId: 'session', instanceId: 'instance', cwd: '/cwd' };
  const old = new PeerGoals(() => entries, append), goal = old.start('old', scope);
  old.note(goal, 'mesh', 'sdk-call');
  entries.push({ type: 'message', message: { role: 'toolResult', toolName: 'mesh', toolCallId: 'sdk-call', details: { run: { id: 'late-sdk-run' } }, isError: false } });
  const reloaded = new PeerGoals(() => entries, append);
  assert.equal(reloaded.current, undefined);
  assert.deepEqual(reloaded.notifications({ ids: ['mesh:late-sdk-run:1:1'] }), [goal.id]);
  const fresh = reloaded.start('new', scope);
  assert.equal(reloaded.allows(fresh, 'mesh', { action: 'resume', runId: 'late-sdk-run' }), false);
  for (let i = 0; i < 1000; i++) reloaded.bindTasks(fresh.id, [`r-${i}`]);
  assert.equal('runs' in fresh, false); assert.equal('agents' in fresh, false); assert.equal('tasks' in reloaded, false);
  reloaded.end(); assert.equal(reloaded.current, undefined);
  assert.equal(reloaded.owner('mesh', 'r-0'), fresh.id); // Not evicted into unrestricted authority.
});

test('forged goal IDs consume bounded sender budget, even when every receiver refuses them', async t => {
  const a = await component('budget-sender', { rpc: true }), b = await component('budget-receiver', { rpc: true });
  try {
    let now = Date.now(); t.mock.method(Date, 'now', () => now);
    for (let round = 0; round < 256; round++) {
      now += 2100;
      await assert.rejects(a.tool('send_pi_message', { target: b.peer.instanceId, message: `forged ${round}`, goalId: 'made-up' }), /goal_not_authorized/);
      assert.equal(info(a).remainingBudget, 255 - round);
    }
    await assert.rejects(a.tool('send_pi_message', { target: b.peer.instanceId, message: 'over limit', goalId: 'another-fake' }), /budget_exhausted/);
    assert.equal(b.calls.length, 0);
  } finally { t.mock.restoreAll(); await b.close(); await a.close(); }
});

test('confirmed goals continue at zero sender budget, but revoked confirmations cannot be reused', async t => {
  const a = await component('confirmed-sender', { rpc: true }), b = await component('confirmed-host');
  try {
    await b.busy();
    const { goalId } = (await b.tool('peer_goal', { action: 'start', objective: 'authorized task' })).details;
    await b.tool('peer_goal', { action: 'bind', goalId, peerIds: [a.peer.instanceId] }); await b.settled();
    const send = text => a.tool('send_pi_message', { target: b.peer.instanceId, message: text, goalId });
    const settle = async () => { b.setIdle(false); b.controller = new AbortController(); b.ctx.signal = b.controller.signal; await b.emit('agent_start'); await b.settled(); };
    await send('confirm valid goal'); await settle();
    assert.equal(info(a).remainingBudget, 256);
    const off = a.bus.on('cross-session:received', event => event.reply({ handled: true }));
    let now = Date.now(); t.mock.method(Date, 'now', () => now);
    for (let round = 0; round < 256; round++) { now += 2100; assert.equal((await wire(b, a, message(`drain ${round}`))).status, 'accepted'); }
    off(); assert.equal(info(a).remainingBudget, 0);
    assert.equal((await send('valid continuation at zero')).details.status, 'submitted'); await settle();
    await b.busy(); await b.tool('peer_goal', { action: 'complete', goalId }); await b.settled();
    await assert.rejects(send('revoked confirmation'), /goal_not_authorized/);
    await assert.rejects(send('cannot reuse failed confirmation'), /budget_exhausted/);
  } finally { t.mock.restoreAll(); await b.close(); await a.close(); }
});

test('rejected goal attempts still spend the receiver token bucket', async () => {
  const a = await component('rate-sender'), b = await component('rate-receiver');
  try {
    for (let round = 0; round < 30; round++) assert.equal((await wire(a, b, message(`rejected ${round}`, { goalId: 'fake' }))).status, 'goal_not_authorized');
    assert.equal((await wire(a, b, message('over rate', { goalId: 'fake' }))).status, 'rate_limited');
  } finally { await b.close(); await a.close(); }
});
