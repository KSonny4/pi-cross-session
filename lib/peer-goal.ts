import { randomUUID } from "node:crypto";
import type { SessionEntry } from "@earendil-works/pi-coding-agent";
import { validId } from "./contract";

export const GOAL_ENTRY = "cross-session:goal-ownership:v1";
type Scope = { sessionId: string; instanceId: string; cwd: string };
type Ownership = { goalId: string; callId?: string; tool?: string; runs?: string[]; agents?: string[] };
export type PeerGoal = { id: string; objective: string; scope: Scope; active: boolean; peers: Map<string, string> };

export class PeerGoals {
  // ponytail: one active objective per Host; use a goal map if concurrent objectives are needed.
  current?: PeerGoal;
  constructor(private readonly entries: () => SessionEntry[], private readonly append: (data: Ownership) => void) {}
  start(objective: string, scope: Scope): PeerGoal {
    if (this.current) throw new Error("Complete or cancel the current peer goal before starting another");
    return this.current = { id: randomUUID(), objective, scope: { ...scope }, active: true, peers: new Map() };
  }
  valid(goal: PeerGoal | undefined, scope: Scope): goal is PeerGoal {
    return !!goal && goal === this.current && goal.active && goal.scope.sessionId === scope.sessionId && goal.scope.instanceId === scope.instanceId && goal.scope.cwd === scope.cwd;
  }
  match(details: { goalId?: string; from: { id: string; instanceId: string } }, scope: Scope): PeerGoal | undefined {
    const goal = this.current;
    return this.valid(goal, scope) && goal.id === details.goalId && goal.peers.get(details.from.instanceId) === details.from.id ? goal : undefined;
  }
  end(): void { if (this.current) this.current.active = false; this.current = undefined; }
  reset(): void { this.end(); } // Revocation never erases task ownership evidence.
  private ownership(entry: SessionEntry): Ownership | undefined {
    if (entry.type !== "custom" || entry.customType !== GOAL_ENTRY) return;
    const data = entry.data as Ownership | undefined;
    return validId(data?.goalId) ? data : undefined;
  }
  private call(callId: string, tool: string): Ownership | undefined {
    return this.entries().map(entry => this.ownership(entry)).find(data => data?.callId === callId && data.tool === tool);
  }
  note(goal: PeerGoal, tool: string, callId: string): void {
    // Persist before execution: even abort/reload before tool_result leaves attribution.
    this.append({ goalId: goal.id, tool, callId });
  }
  owner(kind: "mesh" | "agent", id: unknown): string | undefined {
    if (!validId(id)) return;
    // ponytail: scan existing session journal, no unbounded extension cache; add an indexed
    // on-disk ownership lookup if long-session latency matters. Never evict revocation evidence.
    for (const entry of this.entries()) {
      const data = this.ownership(entry);
      if ((kind === "mesh" ? data?.runs : data?.agents)?.includes(id)) return data!.goalId;
      if (entry.type !== "message" || entry.message.role !== "toolResult" || entry.message.isError) continue;
      const message = entry.message;
      const details = message.details as { run?: { id?: string }; agentId?: string } | undefined;
      if (kind === "mesh" ? message.toolName === "mesh" && details?.run?.id === id : message.toolName === "Agent" && details?.agentId === id) {
        const call = this.call(message.toolCallId, message.toolName);
        if (call) return call.goalId;
      }
    }
  }
  bindTasks(goalId: string, runs: string[] = [], agents: string[] = []): void {
    for (const [kind, ids] of [["mesh", runs], ["agent", agents]] as const) {
      for (const id of ids) {
        const previous = this.owner(kind, id);
        if (previous && previous !== goalId) throw new Error("Task is already bound to a different goal");
      }
    }
    if (runs.length || agents.length) this.append({ goalId, runs, agents });
  }
  record(callId: string, tool: string, details: unknown): void {
    const call = this.call(callId, tool);
    if (!call) return;
    const result = details as { run?: { id?: unknown }; agentId?: unknown } | undefined;
    // Record late successful results against the revoked ID, never restore its grant.
    if (tool === "mesh" && validId(result?.run?.id)) this.bindTasks(call.goalId, [result.run.id]);
    if (tool === "Agent" && validId(result?.agentId)) this.bindTasks(call.goalId, [], [result.agentId]);
  }
  notifications(details: unknown): string[] {
    const ids = (details as { ids?: unknown } | undefined)?.ids;
    if (!Array.isArray(ids)) return [];
    return ids.flatMap(id => {
      if (typeof id !== "string") return [];
      const parts = id.split(":");
      const goalId = this.owner(parts[0] === "mesh" ? "mesh" : "agent", parts[0] === "mesh" ? parts[1] : parts[0]);
      return goalId ? [goalId] : [];
    });
  }
  allows(goal: PeerGoal, tool: string, input: Record<string, unknown>): boolean {
    if (!goal.active) return false;
    if (tool === "Agent") return !input.schedule && (!input.resume || this.owner("agent", input.resume) === goal.id);
    if (tool === "steer_subagent" || tool === "send_subagent") return this.owner("agent", input.agent_id) === goal.id;
    if (tool !== "mesh") return false;
    if (input.action === "run") return true;
    return ["continue", "resume", "retry_failed", "steer", "cancel", "pause", "message_send", "message_broadcast", "growth_decide"].includes(String(input.action)) && this.owner("mesh", input.runId) === goal.id;
  }
}
