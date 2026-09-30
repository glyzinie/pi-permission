import { describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";

import type { PermissionRequest } from "../extensions/permission/protocol.ts";
import {
  loadPermissionRules,
  matchBashPermissionRule,
  matchPermissionRule,
  parsePermissionConfig,
  parsePermissionRules,
} from "../extensions/permission/rules.ts";

const valid = JSON.stringify({
  version: 1,
  language: "ja",
  rules: [
    { tool: "mem0_memory", actions: ["search", "get_all"], decision: "allow" },
    { tool: "mem0_memory", actions: ["add"], decision: "review" },
    { tool: "mem0_memory", actions: ["delete"], decision: "human" },
    {
      tool: "bash",
      commandPrefixes: [["bun", "test"], ["uv", "run", "pytest"]],
      decision: "allow",
    },
    { tool: "legacy_tool", decision: "deny" },
  ],
});

function request(toolName: string, action?: string): PermissionRequest {
  return {
    toolCallId: "call-1",
    toolName,
    originalToolName: toolName,
    input: action ? { action } : {},
    cwd: "/tmp",
    source: "pi",
  };
}

describe("permission.json", () => {
  test("parses and matches tool, action, and Bash prefix rules", () => {
    const config = parsePermissionConfig(valid);
    const rules = parsePermissionRules(valid);
    expect(config.language).toBe("ja");
    expect(rules).toHaveLength(5);
    expect(matchPermissionRule(request("mem0_memory", "search"), rules)?.rule.decision).toBe("allow");
    expect(matchPermissionRule(request("mem0_memory", "unknown"), rules)).toBeUndefined();
    expect(matchPermissionRule(request("legacy_tool"), rules)?.rule.decision).toBe("deny");
    expect(matchBashPermissionRule(["bun", "test", "src"], rules)?.commandPrefix).toEqual(["bun", "test"]);
    expect(matchBashPermissionRule(["bun", "run", "test"], rules)).toBeUndefined();
    expect(matchBashPermissionRule(["./bun", "test"], rules)).toBeUndefined();
  });

  test("keeps linear fallback behavior for external rule arrays", () => {
    const indexed = parsePermissionRules(valid);
    const external = [...indexed];
    for (const rules of [indexed, external]) {
      expect(matchPermissionRule(request("mem0_memory", "get_all"), rules)?.rule.decision).toBe("allow");
      expect(matchPermissionRule(request("mem0_memory", "unknown"), rules)).toBeUndefined();
      expect(matchPermissionRule(request("legacy_tool"), rules)?.rule.decision).toBe("deny");
      expect(matchBashPermissionRule(["uv", "run", "pytest", "-q"], rules)?.commandPrefix)
        .toEqual(["uv", "run", "pytest"]);
      expect(matchBashPermissionRule(["./uv", "run", "pytest"], rules)).toBeUndefined();
    }
  });

  test("rejects unknown versions, fields, decisions, and overlaps", () => {
    for (const value of [
      { version: 2, rules: [] },
      { version: 1, language: "fr", rules: [] },
      { version: 1, extra: true, rules: [] },
      { version: 1, rules: [{ tool: "x", decision: "maybe" }] },
      { version: 1, rules: [
        { tool: "x", decision: "allow" },
        { tool: "x", actions: ["read"], decision: "deny" },
      ] },
      { version: 1, rules: [
        { tool: "x", actions: ["read"], decision: "allow" },
        { tool: "x", actions: ["read"], decision: "deny" },
      ] },
      { version: 1, rules: [
        { tool: "bash", decision: "allow" },
      ] },
      { version: 1, rules: [
        { tool: "bash", actions: ["test"], decision: "allow" },
      ] },
      { version: 1, rules: [
        { tool: "other", commandPrefixes: [["bun", "test"]], decision: "allow" },
      ] },
      { version: 1, rules: [
        {
          tool: "bash",
          commandPrefixes: [["bun", "test"], ["bun", "test", "unit"]],
          decision: "allow",
        },
      ] },
      { version: 1, rules: [
        { tool: "bash", commandPrefixes: [["./bun", "test"]], decision: "allow" },
      ] },
    ]) {
      expect(() => parsePermissionRules(JSON.stringify(value))).toThrow();
    }
  });

  test("loads missing files as no rules and invalid files fail closed", async () => {
    const root = "/tmp/pi-permission-rules-test";
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    expect(await loadPermissionRules(`${root}/missing.json`)).toEqual({ language: "en", rules: [] });
    writeFileSync(`${root}/permission.json`, "not-json");
    const invalid = await loadPermissionRules(`${root}/permission.json`);
    expect(invalid.rules).toEqual([]);
    expect(invalid.error).toBeString();
    rmSync(root, { recursive: true, force: true });
  });
});
