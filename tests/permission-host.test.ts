import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";

import permissionExtension from "../extensions/permission/index.ts";
import permissionTreeSitterBash from "../extensions/permission-tree-sitter-bash/index.ts";
import {
  BASH_ANALYSIS_KIND,
  TREE_SITTER_BASH_PLUGIN_ID,
} from "../extensions/permission-tree-sitter-bash/types.ts";
import {
  PERMISSION_EVENTS,
  PERMISSION_PROTOCOL_VERSION,
} from "../extensions/permission/protocol.ts";

const LEGACY_BASH_GRANT_EVENT = "pi-bash:grant-write";
const originalPiAgentDir = process.env.PI_CODING_AGENT_DIR;
afterEach(() => {
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
});

function harness() {
  const bus = new Map<string, Array<(data: any) => void>>();
  const lifecycle = new Map<string, Array<(event: any, ctx: any) => unknown>>();
  const commands = new Map<string, any>();
  const pi: any = {
    events: {
      on(channel: string, handler: (data: any) => void) {
        const handlers = bus.get(channel) ?? [];
        handlers.push(handler);
        bus.set(channel, handlers);
        return () => {};
      },
      emit(channel: string, data: any) {
        for (const handler of bus.get(channel) ?? []) handler(data);
      },
    },
    on(event: string, handler: (event: any, ctx: any) => unknown) {
      const handlers = lifecycle.get(event) ?? [];
      handlers.push(handler);
      lifecycle.set(event, handlers);
    },
    registerCommand(name: string, command: any) {
      commands.set(name, command);
    },
  };
  return {
    pi,
    commands,
    async emit(event: string, data: any, ctx: any) {
      let result;
      for (const handler of lifecycle.get(event) ?? []) {
        const current = await handler(data, ctx);
        if (current !== undefined) result = current;
      }
      return result;
    },
  };
}

function context(cwd: string, hasUI = false, selection = "Block"): any {
  return {
    cwd,
    hasUI,
    signal: undefined,
    ui: {
      notify() {},
      select: async () => selection,
    },
  };
}

describe("Permission host", () => {
  test("discovers the Bash analyzer and denies protected Bash writes without emitting grants", async () => {
    const root = "/tmp/pi-permission-host-test";
    const cwd = `${root}/workspace`;
    const protectedRoot = `${root}/pi-agent`;
    rmSync(root, { recursive: true, force: true });
    mkdirSync(cwd, { recursive: true });
    mkdirSync(protectedRoot, { recursive: true });
    process.env.PI_CODING_AGENT_DIR = protectedRoot;

    const testHarness = harness();
    permissionExtension(testHarness.pi);
    permissionTreeSitterBash(testHarness.pi);
    const legacyGrants: unknown[] = [];
    testHarness.pi.events.on(LEGACY_BASH_GRANT_EVENT, (event: unknown) => legacyGrants.push(event));

    let status = "";
    await testHarness.commands.get("permission").handler("", {
      ui: { notify: (message: string) => { status = message; } },
    });
    expect(status).toContain("tree-sitter-bash");

    const command = `touch ${protectedRoot}/settings.json`;
    const result = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "bash-1", toolName: "bash", input: { command } },
      context(cwd),
    );
    expect(result).toMatchObject({ block: true });
    expect((result as { reason: string }).reason).toContain("use write or edit");
    expect(legacyGrants).toEqual([]);
    rmSync(root, { recursive: true, force: true });
  });

  test("allows model-approved custom tools without emitting Bash grants", async () => {
    const testHarness = harness();
    permissionExtension(testHarness.pi);
    let reviewCalls = 0;
    testHarness.pi.events.emit(PERMISSION_EVENTS.registerReviewer, {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
      reviewer: {
        id: "test-reviewer",
        review: async () => {
          reviewCalls += 1;
          return { decision: "allow" as const, reason: "low risk" };
        },
      },
    });
    const legacyGrants: unknown[] = [];
    testHarness.pi.events.on(LEGACY_BASH_GRANT_EVENT, (event: unknown) => legacyGrants.push(event));
    const result = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "custom-1", toolName: "custom_tool", input: {} },
      context("/tmp"),
    );
    expect(reviewCalls).toBe(1);
    expect(result).toBeUndefined();
    expect(legacyGrants).toEqual([]);
  });

  test("keeps request snapshots and analyzer identities host-owned", async () => {
    const testHarness = harness();
    permissionExtension(testHarness.pi);
    let frozen = false;
    testHarness.pi.events.emit(PERMISSION_EVENTS.registerAnalyzer, {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
      analyzer: {
        id: "spoofing-analyzer",
        supports(request: any) {
          frozen = Object.isFrozen(request) && Object.isFrozen(request.input);
          try {
            request.toolName = "write";
            request.input.command = "touch outside";
          } catch {
            // Frozen snapshots reject analyzer mutations.
          }
          return true;
        },
        analyze: async () => ({
          analyzer: TREE_SITTER_BASH_PLUGIN_ID,
          kind: BASH_ANALYSIS_KIND,
          data: {
            raw: "ls",
            complete: true,
            dynamic: false,
            opaque: false,
            background: false,
            controlOperators: [],
            commands: [],
            writeTargets: [],
            writeTargetsComplete: true,
            warnings: [],
          },
        } as any),
      },
    });

    const result = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "bash-spoof", toolName: "bash", input: { command: "ls" } },
      context("/tmp"),
    );
    expect(frozen).toBe(true);
    expect(result).toMatchObject({ block: true });
    expect((result as { reason: string }).reason).toContain("Bash analyzer is unavailable or stale");
  });

  test("preserves human fallback for built-in write and edit", async () => {
    const root = "/tmp/pi-permission-human-write-test";
    const protectedRoot = `${root}/pi-agent`;
    mkdirSync(protectedRoot, { recursive: true });
    process.env.PI_CODING_AGENT_DIR = protectedRoot;
    const testHarness = harness();
    permissionExtension(testHarness.pi);
    for (const [toolName, input] of [
      ["write", { path: `${protectedRoot}/settings.json`, content: "{}" }],
      ["edit", { path: `${protectedRoot}/settings.json`, edits: [{ oldText: "a", newText: "b" }] }],
    ] as const) {
      const result = await testHarness.emit(
        "tool_call",
        { type: "tool_call", toolCallId: toolName, toolName, input },
        context(root, true, "Allow once"),
      );
      expect(result).toBeUndefined();
    }
    rmSync(root, { recursive: true, force: true });
  });

  test("loads permission.json on session start", async () => {
    const root = "/tmp/pi-permission-config-test";
    const agentDir = `${root}/agent`;
    mkdirSync(agentDir, { recursive: true });
    writeFileSync(`${agentDir}/permission.json`, JSON.stringify({
      version: 1,
      language: "ja",
      rules: [
        { tool: "mem0_memory", actions: ["search", "get_all"], decision: "allow" },
        { tool: "mem0_memory", actions: ["delete"], decision: "human" },
      ],
    }));
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const testHarness = harness();
    permissionExtension(testHarness.pi);
    await testHarness.emit("session_start", { type: "session_start" }, context(root));

    const read = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "mem0-read", toolName: "mem0_memory", input: { action: "search" } },
      context(root),
    );
    let prompt = "";
    let options: string[] = [];
    const japaneseContext = context(root, true);
    japaneseContext.ui.select = async (title: string, values: string[]) => {
      prompt = title;
      options = values;
      return "拒否";
    };
    const remove = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "mem0-delete", toolName: "mem0_memory", input: { action: "delete" } },
      japaneseContext,
    );
    expect(read).toBeUndefined();
    expect(remove).toMatchObject({
      block: true,
      reason: "ユーザーが拒否しました",
    });
    expect(prompt).toContain("権限の確認: mem0_memory");
    expect(prompt).toContain("理由:");
    expect(options).toEqual(["今回のみ許可", "拒否"]);
    rmSync(root, { recursive: true, force: true });
  });

  test("blocks credential requests when no UI is available", async () => {
    const testHarness = harness();
    permissionExtension(testHarness.pi);
    const result = await testHarness.emit(
      "tool_call",
      { type: "tool_call", toolCallId: "read-1", toolName: "read", input: { path: "~/.ssh/id_ed25519" } },
      context("/tmp"),
    );
    expect(result).toMatchObject({ block: true });
    expect((result as { reason: string }).reason).toContain("no interactive UI");
  });
});
