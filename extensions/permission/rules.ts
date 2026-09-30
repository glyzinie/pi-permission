import { readFile } from "node:fs/promises";

import type { PermissionRequest } from "./protocol.ts";
import type { PermissionLanguage } from "./ui.ts";

const MAX_RULE_FILE_BYTES = 64 * 1024;
const MAX_RULES = 256;
const DECISIONS = new Set(["allow", "review", "human", "deny"] as const);

export type PermissionRuleDecision = "allow" | "review" | "human" | "deny";

export type PermissionCommandPrefix = readonly string[];

export interface PermissionRule {
  tool: string;
  actions?: readonly string[];
  commandPrefixes?: readonly PermissionCommandPrefix[];
  decision: PermissionRuleDecision;
}

export interface PermissionRuleMatch {
  rule: PermissionRule;
  action?: string;
  commandPrefix?: PermissionCommandPrefix;
}

export interface PermissionConfig {
  language: PermissionLanguage;
  rules: readonly PermissionRule[];
}

export interface LoadedPermissionRules extends PermissionConfig {
  error?: string;
}

interface ToolRuleBucket {
  all?: PermissionRule;
  actions: Map<string, PermissionRule>;
}

interface BashRuleCandidate {
  rule: PermissionRule;
  prefix: PermissionCommandPrefix;
}

interface PermissionRuleIndex {
  tools: Map<string, ToolRuleBucket>;
  bashPrefixes: Map<string, BashRuleCandidate[]>;
}

const RULE_INDEXES = new WeakMap<readonly PermissionRule[], PermissionRuleIndex>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isCommandPrefix(
  prefix: readonly string[],
  command: readonly string[],
): boolean {
  return prefix.length <= command.length &&
    prefix.every((token, index) => token === command[index]);
}

function commandPrefixesOverlap(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return isCommandPrefix(left, right) || isCommandPrefix(right, left);
}

function buildPermissionRuleIndex(
  rules: readonly PermissionRule[],
): PermissionRuleIndex {
  const tools = new Map<string, ToolRuleBucket>();
  const bashPrefixes = new Map<string, BashRuleCandidate[]>();

  for (const rule of rules) {
    if (rule.commandPrefixes) {
      for (const prefix of rule.commandPrefixes) {
        const executable = prefix[0]!;
        const candidates = bashPrefixes.get(executable) ?? [];
        candidates.push({ rule, prefix });
        bashPrefixes.set(executable, candidates);
      }
      continue;
    }

    const bucket: ToolRuleBucket = tools.get(rule.tool) ?? {
      actions: new Map<string, PermissionRule>(),
    };
    if (rule.actions) {
      for (const action of rule.actions) bucket.actions.set(action, rule);
    } else {
      bucket.all = rule;
    }
    tools.set(rule.tool, bucket);
  }

  return { tools, bashPrefixes };
}

export function parsePermissionConfig(text: string): PermissionConfig {
  if (Buffer.byteLength(text, "utf8") > MAX_RULE_FILE_BYTES) {
    throw new Error(`permission.json exceeds ${MAX_RULE_FILE_BYTES} bytes`);
  }
  const parsed: unknown = JSON.parse(text);
  if (!isRecord(parsed) || !exactKeys(parsed, ["version", "language", "rules"])) {
    throw new Error("permission.json contains unknown top-level fields");
  }
  if (parsed.version !== 1 || !Array.isArray(parsed.rules)) {
    throw new Error("permission.json requires version 1 and a rules array");
  }
  const language = parsed.language ?? "en";
  if (language !== "en" && language !== "ja") {
    throw new Error("permission.json language must be en or ja");
  }
  if (parsed.rules.length > MAX_RULES) {
    throw new Error(`permission.json supports at most ${MAX_RULES} rules`);
  }

  const rules: PermissionRule[] = [];
  const exactActions = new Set<string>();
  const selectiveTools = new Set<string>();
  const allToolRules = new Set<string>();
  const configuredCommandPrefixes: Array<{
    tool: string;
    prefix: readonly string[];
  }> = [];
  for (const [index, value] of parsed.rules.entries()) {
    if (!isRecord(value) || !exactKeys(value, ["tool", "actions", "commandPrefixes", "decision"])) {
      throw new Error(`rules[${index}] has unknown fields`);
    }
    if (
      typeof value.tool !== "string" ||
      value.tool.length === 0 ||
      value.tool.length > 200 ||
      typeof value.decision !== "string" ||
      !DECISIONS.has(value.decision as PermissionRuleDecision)
    ) {
      throw new Error(`rules[${index}] has an invalid tool or decision`);
    }

    let actions: string[] | undefined;
    if (value.actions !== undefined) {
      if (
        !Array.isArray(value.actions) ||
        value.actions.length === 0 ||
        value.actions.length > 64 ||
        !value.actions.every((action) =>
          typeof action === "string" && action.length > 0 && action.length <= 100,
        )
      ) {
        throw new Error(`rules[${index}].actions must be a non-empty string array`);
      }
      actions = [...new Set(value.actions as string[])];
      if (actions.length !== value.actions.length) {
        throw new Error(`rules[${index}].actions contains duplicates`);
      }
    }

    let commandPrefixes: string[][] | undefined;
    if (value.commandPrefixes !== undefined) {
      if (
        value.tool !== "bash" ||
        actions !== undefined ||
        !Array.isArray(value.commandPrefixes) ||
        value.commandPrefixes.length === 0 ||
        value.commandPrefixes.length > 64
      ) {
        throw new Error(`rules[${index}].commandPrefixes must be a non-empty Bash prefix array`);
      }
      commandPrefixes = [];
      for (const [prefixIndex, prefix] of value.commandPrefixes.entries()) {
        if (
          !Array.isArray(prefix) ||
          prefix.length === 0 ||
          prefix.length > 16 ||
          !prefix.every((token) =>
            typeof token === "string" && token.length > 0 && token.length <= 200,
          ) ||
          (prefix[0] as string).includes("/")
        ) {
          throw new Error(
            `rules[${index}].commandPrefixes[${prefixIndex}] must start with a bare executable and contain 1-16 tokens`,
          );
        }
        const tokens = [...prefix] as string[];
        const overlap = configuredCommandPrefixes.find(
          (item) => item.tool === value.tool && commandPrefixesOverlap(item.prefix, tokens),
        );
        if (overlap) {
          throw new Error(
            `rules[${index}].commandPrefixes[${prefixIndex}] overlaps ${overlap.prefix.join(" ")}`,
          );
        }
        configuredCommandPrefixes.push({ tool: value.tool, prefix: tokens });
        commandPrefixes.push(tokens);
      }
    }

    if (value.tool === "bash" && !commandPrefixes) {
      throw new Error(`rules[${index}] for bash requires commandPrefixes`);
    }

    const selective = actions !== undefined || commandPrefixes !== undefined;
    if (!selective) {
      if (allToolRules.has(value.tool) || selectiveTools.has(value.tool)) {
        throw new Error(`rules[${index}] overlaps another rule for ${value.tool}`);
      }
      allToolRules.add(value.tool);
    } else {
      if (allToolRules.has(value.tool)) {
        throw new Error(`rules[${index}] overlaps an all-action rule for ${value.tool}`);
      }
      selectiveTools.add(value.tool);
    }

    if (actions) {
      for (const action of actions) {
        const key = `${value.tool}\0${action}`;
        if (exactActions.has(key)) {
          throw new Error(`rules[${index}] duplicates ${value.tool}:${action}`);
        }
        exactActions.add(key);
      }
    }

    rules.push(Object.freeze({
      tool: value.tool,
      ...(actions ? { actions: Object.freeze(actions) } : {}),
      ...(commandPrefixes
        ? { commandPrefixes: Object.freeze(commandPrefixes.map((prefix) => Object.freeze(prefix))) }
        : {}),
      decision: value.decision as PermissionRuleDecision,
    }));
  }
  const frozenRules = Object.freeze(rules);
  RULE_INDEXES.set(frozenRules, buildPermissionRuleIndex(frozenRules));
  return { language, rules: frozenRules };
}

export function parsePermissionRules(text: string): readonly PermissionRule[] {
  return parsePermissionConfig(text).rules;
}

export async function loadPermissionRules(path: string): Promise<LoadedPermissionRules> {
  try {
    return parsePermissionConfig(await readFile(path, "utf8"));
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as { code?: unknown }).code === "ENOENT"
    ) {
      return { language: "en", rules: [] };
    }
    return {
      language: "en",
      rules: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function matchPermissionRule(
  request: PermissionRequest,
  rules: readonly PermissionRule[],
): PermissionRuleMatch | undefined {
  const action = typeof request.input.action === "string"
    ? request.input.action
    : undefined;
  const index = RULE_INDEXES.get(rules);
  if (index) {
    const bucket = index.tools.get(request.toolName);
    if (!bucket) return undefined;
    const rule = bucket.all ?? (action === undefined ? undefined : bucket.actions.get(action));
    return rule ? { rule, action } : undefined;
  }

  for (const rule of rules) {
    if (rule.tool !== request.toolName || rule.commandPrefixes) continue;
    if (!rule.actions || (action !== undefined && rule.actions.includes(action))) {
      return { rule, action };
    }
  }
  return undefined;
}

export function matchBashPermissionRule(
  argv: readonly string[],
  rules: readonly PermissionRule[],
): PermissionRuleMatch | undefined {
  if (argv.length === 0 || argv[0]?.includes("/")) return undefined;
  const index = RULE_INDEXES.get(rules);
  if (index) {
    const candidates = index.bashPrefixes.get(argv[0]!);
    if (!candidates) return undefined;
    const match = candidates.find(({ prefix }) => isCommandPrefix(prefix, argv));
    return match ? { rule: match.rule, commandPrefix: match.prefix } : undefined;
  }

  for (const rule of rules) {
    if (rule.tool !== "bash" || !rule.commandPrefixes) continue;
    const commandPrefix = rule.commandPrefixes.find((prefix) =>
      isCommandPrefix(prefix, argv),
    );
    if (commandPrefix) return { rule, commandPrefix };
  }
  return undefined;
}
