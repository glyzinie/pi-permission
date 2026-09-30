import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { homedir } from "node:os";
import { mkdirSync, rmSync, symlinkSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { analyzeBashSource } from "../extensions/permission-tree-sitter-bash/index.ts";
import {
  BASH_ANALYSIS_KIND,
  TREE_SITTER_BASH_PLUGIN_ID,
} from "../extensions/permission-tree-sitter-bash/types.ts";
import { evaluatePolicy } from "../extensions/permission/policy.ts";
import { parsePermissionRules } from "../extensions/permission/rules.ts";
import type {
  PermissionAnalysis,
  PermissionRequest,
} from "../extensions/permission/protocol.ts";

const root = "/tmp/pi-permission-policy-test";
const cwd = `${root}/workspace`;
const protectedRoot = `${root}/pi-agent`;
const originalPiAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalCodexHome = process.env.CODEX_HOME;
const originalPath = process.env.PATH;

beforeEach(() => {
  rmSync(root, { recursive: true, force: true });
  mkdirSync(cwd, { recursive: true });
  mkdirSync(protectedRoot, { recursive: true });
  process.env.PI_CODING_AGENT_DIR = protectedRoot;
  process.env.CODEX_HOME = `${root}/codex`;
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
  if (originalCodexHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = originalCodexHome;
  if (originalPath === undefined) delete process.env.PATH;
  else process.env.PATH = originalPath;
});

function request(toolName: string, input: Record<string, unknown>, requestCwd = cwd): PermissionRequest {
  return {
    toolCallId: "call-1",
    toolName,
    originalToolName: toolName,
    input,
    cwd: requestCwd,
    source: "pi",
  };
}

async function bashAnalysis(command: string): Promise<PermissionAnalysis[]> {
  const data = await analyzeBashSource(command);
  return [{
    analyzer: TREE_SITTER_BASH_PLUGIN_ID,
    kind: BASH_ANALYSIS_KIND,
    data,
    warnings: data.warnings,
  }];
}

describe("permission policy", () => {
  test("allows static trusted commands and compositions", async () => {
    for (const command of ["ls -la", "printf ok | grep ok && echo done"]) {
      const result = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
      expect(result.decision).toBe("allow");
      expect(result.ruleId).toBe("safe-static-shell");
    }
  });

  test("does not cache trusted command resolution across policy evaluations", async () => {
    const command = "ls";
    const analyses = await bashAnalysis(command);

    process.env.PATH = "/nonexistent";
    expect(await evaluatePolicy(
      request("bash", { command }),
      analyses,
    )).toMatchObject({ decision: "review", ruleId: "unrecognized-shell-command" });

    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    expect(await evaluatePolicy(
      request("bash", { command }),
      analyses,
    )).toMatchObject({ decision: "allow", ruleId: "safe-static-shell" });
  });

  test("requires human review when Bash analysis is unavailable", async () => {
    const result = await evaluatePolicy(request("bash", { command: "ls" }), []);
    expect(result).toMatchObject({
      decision: "review",
      route: "human",
      ruleId: "bash-analyzer-unavailable",
    });
  });

  test("keeps built-in writes reviewable but denies protected Bash writes", async () => {
    const target = `${protectedRoot}/settings.json`;
    const direct = await evaluatePolicy(
      request("write", { path: target, content: "{}" }),
      [],
    );
    const command = `touch ${target}`;
    const bash = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
    expect(direct).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "protected-config-write",
    });
    expect(bash).toMatchObject({
      decision: "deny",
      ruleId: "bash-protected-write-disallowed",
    });
    expect(bash.reason).toContain("use write or edit");
  });

  test("keeps auth files, broad credential scans, and external paths human-only", async () => {
    const direct = await evaluatePolicy(
      request("write", { path: `${protectedRoot}/auth.json`, content: "{}" }),
      [],
    );
    const command = "cat < ~/.ssh/id_ed25519";
    const redirect = await evaluatePolicy(
      request("bash", { command }),
      await bashAnalysis(command),
    );
    const broad = await evaluatePolicy(
      request("grep", { path: homedir(), pattern: "token" }, homedir()),
      [],
    );
    const external = await evaluatePolicy(
      request("mcp:read_file", { path: "~/.git-credentials" }),
      [],
    );
    expect(direct).toMatchObject({ decision: "review", route: "human", ruleId: "credential-write" });
    expect(redirect).toMatchObject({ decision: "review", route: "human", ruleId: "credential-shell-access" });
    expect(broad).toMatchObject({ decision: "review", route: "human", ruleId: "credential-read" });
    expect(external).toMatchObject({ decision: "review", route: "human", ruleId: "credential-external-tool" });
  });

  test("keeps credential paths in attached command options human-only", async () => {
    const credential = `${homedir()}/.ssh/config`;
    const linkedCredential = `${root}/credential-option`;
    symlinkSync(credential, linkedCredential);

    for (const command of [
      `file --files-from=${credential}`,
      `file -f${linkedCredential}`,
      `rg --ignore-file=${credential} pattern .`,
    ]) {
      const result = await evaluatePolicy(
        request("bash", { command }),
        await bashAnalysis(command),
      );
      expect(result).toMatchObject({
        decision: "review",
        route: "human",
        ruleId: "credential-shell-access",
      });
    }
  });

  test("normalizes file URL paths before applying read policy", async () => {
    const credentialUrl = pathToFileURL(`${homedir()}/.ssh`).href;
    expect(await evaluatePolicy(
      request("ls", { path: credentialUrl }),
      [],
    )).toMatchObject({
      decision: "review",
      route: "human",
      ruleId: "credential-read",
      details: { target: `${homedir()}/.ssh` },
    });

    expect(await evaluatePolicy(
      request("ls", { path: pathToFileURL(cwd).href }),
      [],
    )).toMatchObject({ decision: "allow", ruleId: "builtin-read" });
  });

  test("checks cwd when an optional built-in read path is omitted", async () => {
    const calls: Array<{ toolName: string; input: Record<string, unknown> }> = [
      { toolName: "grep", input: { pattern: "token" } },
      { toolName: "find", input: { pattern: "*" } },
      { toolName: "ls", input: {} },
    ];

    for (const { toolName, input } of calls) {
      const broad = await evaluatePolicy(request(toolName, input, homedir()), []);
      expect(broad).toMatchObject({
        decision: "review",
        route: "human",
        ruleId: "credential-read",
        details: { target: homedir() },
      });

      const scoped = await evaluatePolicy(request(toolName, input), []);
      expect(scoped).toMatchObject({
        decision: "allow",
        ruleId: "builtin-read",
        details: { target: cwd },
      });
    }
  });

  test("does not auto-allow temp symlinks whose canonical target is outside temp", async () => {
    const link = `${root}/temp-link`;
    symlinkSync(`${homedir()}/permission-symlink-target-${process.pid}`, link);
    const result = await evaluatePolicy(
      request("write", { path: link, content: "x" }),
      [],
    );
    expect(result).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "outside-workspace-write",
    });
  });

  test("does not cache target identities across policy evaluations", async () => {
    const link = `${root}/moving-link`;
    symlinkSync(`${cwd}/inside.txt`, link);
    expect(await evaluatePolicy(
      request("write", { path: link, content: "x" }),
      [],
    )).toMatchObject({ decision: "allow" });

    rmSync(link);
    symlinkSync(`${homedir()}/outside.txt`, link);
    expect(await evaluatePolicy(
      request("write", { path: link, content: "x" }),
      [],
    )).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "outside-workspace-write",
    });
  });

  test("does not auto-allow HOME as a workspace", async () => {
    const result = await evaluatePolicy(
      request("write", { path: `${homedir()}/ordinary-file`, content: "x" }, homedir()),
      [],
    );
    expect(result).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "outside-workspace-write",
    });
  });

  test("denies Bash writes outside the sandbox", async () => {
    const target = `${homedir()}/permission-outside-${process.pid}.txt`;
    for (const command of [
      `touch ${target}`,
      `touch ${cwd}/inside.txt ${target}`,
    ]) {
      const result = await evaluatePolicy(
        request("bash", { command }),
        await bashAnalysis(command),
      );
      expect(result).toMatchObject({
        decision: "deny",
        ruleId: "bash-outside-sandbox-write-disallowed",
      });
      expect(result.reason).toContain("use write or edit");
    }
  });

  test("denies Bash deletion and directs the model to trash", async () => {
    for (const command of ["rm file.txt", "rmdir old-dir", "find . -delete", "git clean -fd"]) {
      const result = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
      expect(result).toMatchObject({ decision: "deny", ruleId: "bash-deletion-disallowed" });
      expect(result.reason).toContain("trash");
    }
  });

  test("routes static commands with unmodeled effects to model review", async () => {
    for (const command of ["npm test", "npm run build", "cargo test"]) {
      const result = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
      expect(result.decision).toBe("review");
      expect(result.ruleId).toBe("unrecognized-shell-command");
    }
  });

  test("does not auto-allow executable aliases or side-effecting options", async () => {
    for (const command of [
      "./cat file",
      "tree -o output.txt",
      "rg --pre ./filter pattern",
      "file -C -m magic",
    ]) {
      const result = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
      expect(result.decision).not.toBe("allow");
    }
  });

  test("allows configured prefixes across static shell compositions without weakening guards", async () => {
    const rules = parsePermissionRules(JSON.stringify({
      version: 1,
      rules: [{
        tool: "bash",
        commandPrefixes: [
          ["bun", "test"],
          ["bun", "run", "test"],
          ["uv", "run", "pytest"],
        ],
        decision: "allow",
      }],
    }));

    for (const command of [
      "bun test",
      "bun test src",
      "bun run test",
      "uv run pytest -q",
      "bun test && true",
      "bun test || false",
      "bun test | head -n 1",
      "bun test |& head -n 1",
      "bun test; bun run test",
      "bun test\ntrue",
    ]) {
      const result = await evaluatePolicy(
        request("bash", { command }),
        await bashAnalysis(command),
        rules,
      );
      expect(result).toMatchObject({ decision: "allow", ruleId: "configured-tool-rule" });
    }

    for (const command of [
      "PATH=/tmp bun test",
      "bun test $FILTER",
      "bun test $(true)",
      "bun test &",
    ]) {
      const result = await evaluatePolicy(
        request("bash", { command }),
        await bashAnalysis(command),
        rules,
      );
      expect(result).toMatchObject({ decision: "review", ruleId: "complex-shell-command" });
    }

    for (const command of [
      "./bun test",
      "bun test && npm test",
      "bun test | tree -o output.txt",
    ]) {
      const result = await evaluatePolicy(
        request("bash", { command }),
        await bashAnalysis(command),
        rules,
      );
      expect(result).toMatchObject({ decision: "review", ruleId: "unrecognized-shell-command" });
    }

    const deletion = "bun test; rm file.txt";
    expect(await evaluatePolicy(
      request("bash", { command: deletion }),
      await bashAnalysis(deletion),
      rules,
    )).toMatchObject({ decision: "deny", ruleId: "bash-deletion-disallowed" });

    const outside = `${homedir()}/permission-test-output-${process.pid}.txt`;
    const redirect = `bun test > ${outside}`;
    expect(await evaluatePolicy(
      request("bash", { command: redirect }),
      await bashAnalysis(redirect),
      rules,
    )).toMatchObject({ decision: "deny", ruleId: "bash-outside-sandbox-write-disallowed" });
  });

  test("uses the strongest configured decision across a static composition", async () => {
    const rules = parsePermissionRules(JSON.stringify({
      version: 1,
      rules: [
        { tool: "bash", commandPrefixes: [["bun", "test"]], decision: "allow" },
        { tool: "bash", commandPrefixes: [["deploy"]], decision: "human" },
        { tool: "bash", commandPrefixes: [["blocked"]], decision: "deny" },
      ],
    }));

    const human = "bun test && deploy";
    expect(await evaluatePolicy(
      request("bash", { command: human }),
      await bashAnalysis(human),
      rules,
    )).toMatchObject({ decision: "review", route: "human", ruleId: "configured-tool-rule" });

    const denied = "deploy || blocked";
    expect(await evaluatePolicy(
      request("bash", { command: denied }),
      await bashAnalysis(denied),
      rules,
    )).toMatchObject({ decision: "deny", ruleId: "configured-tool-rule" });
  });

  test("routes dynamic credential references to human review", async () => {
    const command = "cat \"$HOME/.ssh/id_ed25519\"";
    const result = await evaluatePolicy(request("bash", { command }), await bashAnalysis(command));
    expect(result).toMatchObject({
      decision: "review",
      route: "human",
      ruleId: "credential-shell-access",
    });
  });

  test("requires review for tool names from removed extensions", async () => {
    for (const toolName of ["ask", "web_search", "web_fetch"]) {
      expect(await evaluatePolicy(request(toolName, {}), [])).toMatchObject({
        decision: "review",
        route: "model-then-human",
        ruleId: "custom-tool",
      });
    }
  });

  test("applies exact action rules from permission.json", async () => {
    const rules = parsePermissionRules(JSON.stringify({
      version: 1,
      rules: [
        { tool: "mem0_memory", actions: ["search", "get_all"], decision: "allow" },
        { tool: "mem0_memory", actions: ["add"], decision: "review" },
        { tool: "mem0_memory", actions: ["delete"], decision: "human" },
      ],
    }));
    for (const action of ["search", "get_all"]) {
      const result = await evaluatePolicy(request("mem0_memory", { action }), [], rules);
      expect(result).toMatchObject({ decision: "allow", ruleId: "configured-tool-rule" });
    }
    expect(await evaluatePolicy(request("mem0_memory", { action: "add" }), [], rules)).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "configured-tool-rule",
    });
    expect(await evaluatePolicy(request("mem0_memory", { action: "delete" }), [], rules)).toMatchObject({
      decision: "review",
      route: "human",
      ruleId: "configured-tool-rule",
    });
    expect(await evaluatePolicy(request("mem0_memory", { action: "unknown" }), [], rules)).toMatchObject({
      decision: "review",
      route: "model-then-human",
      ruleId: "custom-tool",
    });
  });

  test("rejects stale analysis snapshots", async () => {
    const analyses = await bashAnalysis("ls");
    const result = await evaluatePolicy(request("bash", { command: "rm -rf /" }), analyses);
    expect(result).toMatchObject({ decision: "review", route: "human", ruleId: "bash-analyzer-unavailable" });
  });
});
