// Two-machine simulation: own agent dir + TLS-PSK gateway, driven over IPC.
// Parent spawns one worker per machine with PI_CROSS_TEST_REMOTE_PSK and
// PI_CROSS_TEST_REMOTE_PEERS (JSON array of "127.0.0.1:port").
import fs from 'node:fs';
import path from 'node:path';
const [name, portText] = process.argv.slice(2);
const root = process.env.PI_CROSS_TEST_PRIVATE_ROOT;
process.env.PI_CODING_AGENT_DIR = path.join(root, `remote-${name}-${process.pid}`);
fs.mkdirSync(process.env.PI_CODING_AGENT_DIR, { recursive: true, mode: 0o700 });
fs.writeFileSync(path.join(process.env.PI_CODING_AGENT_DIR, 'cross-session-remote.json'), JSON.stringify({
  listen: `127.0.0.1:${portText}`,
  psk: process.env.PI_CROSS_TEST_REMOTE_PSK,
  peers: JSON.parse(process.env.PI_CROSS_TEST_REMOTE_PEERS),
}), { mode: 0o600 });
const { make, tool } = await import('./sdk.mjs');
const x = await make(name, { remote: true });
const { token: _token, ...peer } = x.peer;
process.send({ type: 'ready', peer, pid: process.pid });
process.on('message', async command => {
  try {
    if (command.type === 'list') {
      const result = await tool(x, 'list_pi').execute('fixture-list', {});
      process.send({
        type: 'listed', text: result.content[0].text,
        details: { peers: result.details.peers, remoteDiagnostics: result.details.remoteDiagnostics ?? [] },
      });
    } else if (command.type === 'send') {
      try {
        const result = await tool(x, 'send_pi_message').execute('fixture-send', {
          target: command.target,
          message: command.message,
          ...(command.goalId ? { goalId: command.goalId } : {}),
        });
        process.send({ type: 'sent', id: command.id, status: result.details.status, messageId: result.details.messageId, text: result.content[0].text });
      } catch (error) {
        process.send({ type: 'sendFailed', id: command.id, error: String(error?.message ?? error), code: error?.code ?? '' });
      }
    } else if (command.type === 'received') {
      const messages = x.session.agent.state.messages
        .filter(m => m.role === 'custom' && m.customType === 'cross-session')
        .map(m => ({
          text: m.details?.text,
          content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
          from: m.details?.from,
          remoteMachine: m.details?.remoteMachine,
          messageId: m.details?.messageId,
        }));
      process.send({ type: 'received', id: command.id, messages });
    } else if (command.type === 'close') {
      await x.close(); process.disconnect();
    }
  } catch (error) { process.send({ type: 'failure', error: error.stack }); process.exitCode = 1; process.disconnect(); }
});
