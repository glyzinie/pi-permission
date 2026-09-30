import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";

import bashExtension from "../extensions/bash/index.ts";
import type { SandboxRuntime } from "../extensions/bash/sandbox-exec.ts";

const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
afterEach(() => {
  if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
});

interface CapturedExecution {
  command: string;
  cwd: string;
}

function harness() {
  const lifecycle = new Map<string, Array<(event: any, ctx: any) => unknown>>();
  const captured: CapturedExecution[] = [];
  const sandboxStarts: Array<{ cwd: string; shellPath?: string }> = [];
  let tool: any;
  let closeCount = 0;

  const pi: any = {
    on(event: string, handler: (event: any, ctx: any) => unknown) {
      const handlers = lifecycle.get(event) ?? [];
      handlers.push(handler);
      lifecycle.set(event, handlers);
    },
    registerTool(definition: any) {
      tool = definition;
    },
  };

  bashExtension(pi, {
    platform: "darwin",
    createSandbox(cwd: string, shellPath?: string): SandboxRuntime {
      sandboxStarts.push({ cwd, shellPath });
      return {
        operations: {
          exec(command, executionCwd, options) {
            captured.push({ command, cwd: executionCwd });
            options.onData(Buffer.from("ok"));
            return Promise.resolve({ exitCode: 0 });
          },
        },
        close() {
          closeCount += 1;
        },
      };
    },
  });

  return {
    captured,
    sandboxStarts,
    get closeCount() {
      return closeCount;
    },
    get tool() {
      return tool;
    },
    async emitLifecycle(event: string, data: any, ctx: any) {
      let result: unknown;
      for (const handler of lifecycle.get(event) ?? []) {
        result = (await handler(data, ctx)) ?? result;
      }
      return result;
    },
  };
}

function context(cwd: string): any {
  return {
    cwd,
    model: undefined,
    thinkingLevel: "off",
    hasUI: false,
    isProjectTrusted: () => false,
    sessionManager: {
      getSessionId: () => "test-session",
      getSessionFile: () => undefined,
    },
  };
}

describe("bash dispatcher", () => {
  test("fails closed on macOS until the sandbox runtime is initialized", async () => {
    const testHarness = harness();
    await expect(
      testHarness.tool.execute(
        "before-session",
        { command: "printf blocked" },
        undefined,
        undefined,
        context("/tmp"),
      ),
    ).rejects.toThrow("sandbox is not initialized");
  });

  test("sandboxes only the Bash tool and keeps the session settings snapshot", async () => {
    const root = "/tmp/pi-bash-dispatch-test";
    const agentDir = `${root}/agent`;
    const cwd = `${root}/workspace`;
    rmSync(root, { recursive: true, force: true });
    mkdirSync(agentDir, { recursive: true });
    mkdirSync(cwd, { recursive: true });
    writeFileSync(
      `${agentDir}/settings.json`,
      JSON.stringify({ shellPath: "/bin/zsh", shellCommandPrefix: "set -e" }),
    );
    process.env.PI_CODING_AGENT_DIR = agentDir;

    const testHarness = harness();
    expect(testHarness.tool.promptSnippet).toBe(
      "Execute shell commands only when no dedicated tool applies",
    );
    expect(testHarness.tool.promptGuidelines).toEqual([]);

    const ctx = context(cwd);
    await testHarness.emitLifecycle("session_start", { type: "session_start" }, ctx);
    expect(testHarness.sandboxStarts).toEqual([{ cwd, shellPath: "/bin/zsh" }]);

    // Tool-written settings cannot change the active session shell or prefix.
    writeFileSync(
      `${agentDir}/settings.json`,
      JSON.stringify({ shellPath: "/bin/bash", shellCommandPrefix: "malicious" }),
    );

    const result = await testHarness.tool.execute(
      "base",
      { command: "printf base" },
      undefined,
      undefined,
      ctx,
    );
    expect(result.content[0]?.text).toBe("ok");
    expect(testHarness.captured.at(-1)).toEqual({
      command: "set -e\nprintf base",
      cwd,
    });

    const userBash = await testHarness.emitLifecycle(
      "user_bash",
      { type: "user_bash", command: "pwd", cwd, excludeFromContext: false },
      ctx,
    );
    expect(userBash).toBeUndefined();

    await testHarness.emitLifecycle("session_shutdown", { type: "session_shutdown" }, ctx);
    expect(testHarness.closeCount).toBe(1);
    rmSync(root, { recursive: true, force: true });
  });
});
