import test from 'node:test';
import assert from 'node:assert/strict';
import { Type } from 'typebox';
import { make, command, tool, until } from './support/sdk.mjs';
import { info } from './support/component.mjs';

test('real SDK/IPC: a locally bound goal drives 20 peer task rounds, then explicitly completes', async () => {
  let executions = 0;
  const worker = await make('goal-sdk-worker'), host = await make('goal-sdk-host', { rpc: true, tools: ['peer_goal', 'mesh'], extra: pi => pi.registerTool({
    name: 'mesh', label: 'Inert Mesh', description: 'Authorization fixture, no actual children', parameters: Type.Object({ action: Type.Literal('run') }),
    async execute() { executions++; return { content: [{ type: 'text', text: 'created' }], details: { run: { id: `sdk-goal-run-${executions}` } } }; },
  }) });
  const sendGoal = (goalId, message) => tool(worker, 'send_pi_message').execute('fixture-send', { target: host.peer.instanceId, message, goalId });
  try {
    host.session.setActiveToolsByName(['peer_goal', 'mesh']);
    host.setToolCall({ name: 'peer_goal', arguments: { action: 'start', objective: 'Repair the metric and finish the authorized verification' } });
    await command(host, 'Authorize this repair goal and collaborate with the worker');
    const start = host.session.agent.state.messages.find(m => m.role === 'toolResult' && m.toolName === 'peer_goal');
    assert.equal(start.isError, false); const goalId = start.details.goalId; assert.ok(goalId);
    host.setToolCall({ name: 'peer_goal', arguments: { action: 'bind', goalId, peerIds: [worker.peer.instanceId] } });
    await command(host, 'Bind this exact worker to the original repair goal');
    assert.equal(host.calls.length, 4);
    for (let round = 1; round <= 20; round++) {
      host.setToolCall({ name: 'mesh', arguments: { action: 'run' } });
      assert.equal((await sendGoal(goalId, `Proceed with original goal phase ${round}`)).details.status, 'submitted');
      await until(() => host.calls.length === 4 + round * 2 && host.session.isIdle);
      assert.equal(executions, round, `peer phase ${round}`); assert.equal(info(host).stopped, false);
    }
    const state = await tool(host, 'peer_goal').execute('fixture-status', { action: 'status' }, undefined, undefined, host.session.extensionRunner.createContext());
    assert.equal(state.details.goalId, goalId);
    assert.equal(host.session.sessionManager.getEntries().filter(entry => entry.type === 'custom' && entry.customType === 'cross-session:goal-ownership:v1' && entry.data?.runs?.length).length, 20, 'actual successful tool results bind handles to the goal');
    assert.equal(info(host).remainingBudget, 256, 'scoped inbound messages have no lifetime round quota');
    host.setToolCall({ name: 'peer_goal', arguments: { action: 'complete', goalId } });
    await sendGoal(goalId, 'Verification is complete; close the original goal');
    await until(() => host.calls.length === 46 && host.session.isIdle);
    const end = host.session.agent.state.messages.filter(m => m.role === 'toolResult' && m.toolName === 'peer_goal').at(-1);
    assert.equal(end.isError, false); assert.equal(end.details.goalId, null);
    await assert.rejects(sendGoal(goalId, 'late goal continuation'), /goal_not_authorized/);
    assert.equal(executions, 20);
    await host.session.reload(); host.session.setActiveToolsByName(['peer_goal', 'mesh']);
    await command(host, 'A fresh user turn after reload');
    host.setToolCall({ name: 'mesh', arguments: { action: 'run' } });
    await host.session.sendCustomMessage({ customType: 'subagent-notification', content: 'Old goal completion after actual SDK reload', display: true, details: { ids: ['mesh:sdk-goal-run-1:1:1'] } }, { triggerTurn: true, deliverAs: 'followUp' });
    await until(() => host.calls.length === 49 && host.session.isIdle);
    assert.equal(executions, 20, 'actual SDK reload must not launder old goal completions');
    assert.equal(host.session.agent.state.messages.filter(m => m.role === 'toolResult' && m.toolName === 'mesh').at(-1).isError, true);
    assert.deepEqual(host.errors, []); assert.deepEqual(worker.errors, []);
  } finally { await host.close(); await worker.close(); }
});
