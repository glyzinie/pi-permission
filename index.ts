import { homedir, tmpdir } from "node:os";
import { isAbsolute, relative, resolve, sep } from "node:path";

import type {
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";

export const PERMISSION_PROTOCOL_VERSION = 2;

export const PERMISSION_EVENTS = {
  discover: "pi-permission:discover",
  registerAnalyzer: "pi-permission:register-analyzer",
  registerReviewer: "pi-permission:register-reviewer",
} as const;

export type PermissionDecision = "allow" | "review" | "deny";
export type ReviewerDecision = "allow" | "defer";

export interface PermissionRequest {
  protocolVersion: number;
  toolCallId: string;
  /** Normalized tool name. MCP proxy calls become `mcp:<inner-tool>`. */
  toolName: string;
  /** Original Pi tool name before normalization. */
  originalToolName: string;
  input: Record<string, unknown>;
  cwd: string;
  source: "pi" | "mcp";
}

export interface BashRedirect {
  operator: string;
  target?: string;
}

export interface BashCommandNode {
  argv: string[];
  assignments: string[];
  redirects: BashRedirect[];
}

export interface BashStructuralAnalysis {
  raw: string;
  commands: BashCommandNode[];
  operators: string[];
  hasPipeline: boolean;
  background: boolean;
  dynamic: boolean;
  substitutions: string[];
  warnings: string[];
}

export interface PermissionAnalyzerResult {
  analyzer: string;
  kind: string;
  data: unknown;
  warnings?: string[];
}

export interface PermissionAnalyzer {
  id: string;
  priority?: number;
  supports(request: PermissionRequest): boolean;
  analyze(
    request: PermissionRequest,
    ctx: ExtensionContext,
  ):
    | Promise<PermissionAnalyzerResult | undefined>
    | PermissionAnalyzerResult
    | undefined;
}

export interface PermissionPolicyResult {
  decision: PermissionDecision;
  reason: string;
  /** Whether a model reviewer is allowed to auto-approve this request. */
  autoReview: boolean;
  /** If true, skip model reviewers and require explicit user approval. */
  humanOnly: boolean;
  details?: Record<string, unknown>;
}

export interface PermissionReview {
  reviewer: string;
  decision: ReviewerDecision;
  reason: string;
  details?: Record<string, unknown>;
}

export interface PermissionReviewer {
  id: string;
  priority?: number;
  review(
    request: PermissionRequest,
    policy: PermissionPolicyResult,
    analyses: readonly PermissionAnalyzerResult[],
    ctx: ExtensionContext,
  ): Promise<PermissionReview>;
}

export interface RegisterAnalyzerEvent {
  protocolVersion: number;
  analyzer: PermissionAnalyzer;
}

export interface RegisterReviewerEvent {
  protocolVersion: number;
  reviewer: PermissionReviewer;
}

const BUILTIN_READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
const BUILTIN_WRITE_TOOLS = new Set(["write", "edit"]);

const KNOWN_READ_ONLY_CUSTOM_TOOLS = new Set([
  "web_search",
  "fetch_markdown",
  "fetch_content",
  "source_check",
  "get_search_content",
  "github_search",
  "grepapp_search",
  "kagi_search",
  "jina_read",
  "resolve-library-id",
  "query-docs",
  "context7_resolve_library_id",
  "context7_query_docs",
  "questionnaire",
]);

const MUTATION_TOOL_NAME =
  /(?:^|[_:.\-/])(create|update|edit|write|delete|remove|send|publish|deploy|execute|run|merge|close|approve|archive|trash|move|rename|upload|install|apply)(?:$|[_:.\-/])/i;

const SAFE_PROVIDER_MARKER = /(?:kagi|jina|grepapp|context7)/i;

const SAFE_SIMPLE_COMMANDS = new Set([
  "pwd",
  "ls",
  "tree",
  "rg",
  "grep",
  "fd",
  "cat",
  "head",
  "tail",
  "wc",
  "file",
  "stat",
  "echo",
  "printf",
  "true",
  "false",
  "test",
  "[",
  "cd",
]);

const REVIEW_COMMANDS = new Set([
  "rm",
  "rmdir",
  "mv",
  "cp",
  "mkdir",
  "touch",
  "install",
  "ln",
  "chmod",
  "chown",
  "chgrp",
  "curl",
  "wget",
  "ssh",
  "scp",
  "sftp",
  "rsync",
  "kill",
  "killall",
  "pkill",
  "launchctl",
  "systemctl",
  "gh",
  "docker",
  "podman",
]);

const HUMAN_ONLY_COMMANDS = new Set(["sudo", "doas", "su"]);

const HARD_DENY_COMMAND_PATTERNS: Array<[RegExp, string]> = [
  [
    /\brm\s+-[^\n]*r[^\n]*f[^\n]*\s+(?:\/|\/\*|~\/?)(?:\s|$)/i,
    "recursive deletion of a filesystem or home root",
  ],
  [
    /\b(?:mkfs(?:\.[a-z0-9]+)?|newfs(?:_[a-z0-9]+)?)\b/i,
    "filesystem formatting",
  ],
  [
    /\bdiskutil\s+(?:eraseDisk|eraseVolume|partitionDisk|apfs\s+deleteContainer)\b/i,
    "disk erase/partition operation",
  ],
  [/\bdd\b[^\n]*\bof=\/dev\//i, "raw device write"],
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAnalyzerRegistration(value: unknown): value is RegisterAnalyzerEvent {
  if (!isRecord(value)) return false;
  if (value.protocolVersion !== PERMISSION_PROTOCOL_VERSION) return false;
  const analyzer = value.analyzer;
  if (!isRecord(analyzer)) return false;
  return (
    typeof analyzer.id === "string" &&
    typeof analyzer.supports === "function" &&
    typeof analyzer.analyze === "function"
  );
}

function isReviewerRegistration(value: unknown): value is RegisterReviewerEvent {
  if (!isRecord(value)) return false;
  if (value.protocolVersion !== PERMISSION_PROTOCOL_VERSION) return false;
  const reviewer = value.reviewer;
  if (!isRecord(reviewer)) return false;
  return typeof reviewer.id === "string" && typeof reviewer.review === "function";
}

function sortByPriority<T extends { priority?: number; id: string }>(
  items: Iterable<T>,
): T[] {
  return [...items].sort((a, b) => {
    const priority = (b.priority ?? 0) - (a.priority ?? 0);
    return priority !== 0 ? priority : a.id.localeCompare(b.id);
  });
}

function expandPath(path: string, cwd: string): string {
  if (path === "~") return resolve(homedir());
  if (path.startsWith("~/") || path.startsWith(`~${sep}`)) {
    return resolve(homedir(), path.slice(2));
  }
  return isAbsolute(path) ? resolve(path) : resolve(cwd, path);
}

function isInside(root: string, target: string): boolean {
  const rel = relative(resolve(root), resolve(target));
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function isDirectChild(root: string, target: string): boolean {
  const rel = relative(resolve(root), resolve(target));
  return rel !== "" && rel !== ".." && !isAbsolute(rel) && !rel.includes(sep);
}

function extraWritableRoots(): string[] {
  const home = resolve(homedir());
  return [resolve(home, ".pi", "agent"), resolve(home, ".codex")];
}

function tempRoots(): string[] {
  const roots = new Set<string>([
    resolve(tmpdir()),
    "/tmp",
    "/private/tmp",
    "/private/var/tmp",
  ]);
  return [...roots];
}

function isTempPath(target: string): boolean {
  return tempRoots().some((root) => isInside(root, target));
}

function isCredentialPath(target: string): boolean {
  const home = resolve(homedir());
  const roots = [
    resolve(home, ".ssh"),
    resolve(home, ".gnupg"),
    resolve(home, ".aws"),
  ];
  if (roots.some((root) => isInside(root, target))) return true;

  const files = [
    resolve(home, ".netrc"),
    resolve(home, ".npmrc"),
    resolve(home, ".pypirc"),
    resolve(home, ".docker", "config.json"),
    resolve(home, ".config", "gh", "hosts.yml"),
    resolve(home, ".config", "gcloud", "application_default_credentials.json"),
    resolve(home, ".pi", "agent", "auth.json"),
    resolve(home, ".codex", "auth.json"),
  ];
  return files.some((file) => resolve(target) === file);
}

function isHumanOnlyWritePath(target: string): boolean {
  const home = resolve(homedir());
  const criticalRoots = [resolve(home, ".pi", "agent", "extensions")];
  if (criticalRoots.some((root) => isInside(root, target))) return true;

  const criticalFiles = [
    resolve(home, ".pi", "agent", "settings.json"),
    resolve(home, ".pi", "agent", "auth.json"),
    resolve(home, ".codex", "auth.json"),
    resolve(home, ".codex", "config.toml"),
  ];
  return criticalFiles.some((file) => resolve(target) === file);
}

function pathFromInput(input: Record<string, unknown>): string | undefined {
  for (const key of ["path", "file", "filePath", "file_path", "target"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim() !== "") return value;
  }
  return undefined;
}

function policy(
  decision: PermissionDecision,
  reason: string,
  options: {
    autoReview?: boolean;
    humanOnly?: boolean;
    details?: Record<string, unknown>;
  } = {},
): PermissionPolicyResult {
  return {
    decision,
    reason,
    autoReview: options.autoReview ?? decision === "review",
    humanOnly: options.humanOnly ?? false,
    details: options.details,
  };
}

function normalizeRequest(event: ToolCallEvent, ctx: ExtensionContext): PermissionRequest {
  const originalInput = isRecord(event.input) ? event.input : {};

  // pi-mcp-adapter proxy mode: { tool: "...", args: { ... } }
  if (event.toolName === "mcp" && typeof originalInput.tool === "string") {
    return {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
      toolCallId: event.toolCallId,
      toolName: `mcp:${originalInput.tool}`,
      originalToolName: event.toolName,
      input: isRecord(originalInput.args) ? originalInput.args : originalInput,
      cwd: ctx.cwd,
      source: "mcp",
    };
  }

  return {
    protocolVersion: PERMISSION_PROTOCOL_VERSION,
    toolCallId: event.toolCallId,
    toolName: event.toolName,
    originalToolName: event.toolName,
    input: originalInput,
    cwd: ctx.cwd,
    source: "pi",
  };
}

function isKnownReadOnlyCustomTool(toolName: string): boolean {
  const normalized = toolName.toLowerCase();
  if (KNOWN_READ_ONLY_CUSTOM_TOOLS.has(normalized)) return true;
  if (SAFE_PROVIDER_MARKER.test(normalized) && !MUTATION_TOOL_NAME.test(normalized)) {
    return true;
  }
  return false;
}

function evaluateReadTool(request: PermissionRequest): PermissionPolicyResult {
  const rawPath = pathFromInput(request.input);
  if (!rawPath) {
    return policy("allow", `${request.toolName} is a built-in read-only tool`);
  }

  const target = expandPath(rawPath, request.cwd);
  if (isCredentialPath(target)) {
    return policy("review", `credential path access requires explicit approval: ${rawPath}`, {
      autoReview: false,
      humanOnly: true,
      details: { target },
    });
  }

  return policy("allow", `${request.toolName} is read-only`, { details: { target } });
}

function evaluateWriteTool(request: PermissionRequest): PermissionPolicyResult {
  const rawPath = pathFromInput(request.input);
  if (!rawPath) {
    return policy("review", `${request.toolName} has no usable target path`, {
      autoReview: false,
      humanOnly: true,
    });
  }

  const target = expandPath(rawPath, request.cwd);
  const home = resolve(homedir());
  const sessionRoot = resolve(request.cwd);

  if (isCredentialPath(target)) {
    return policy("review", `credential path modification requires explicit approval: ${rawPath}`, {
      autoReview: false,
      humanOnly: true,
      details: { target },
    });
  }

  if (isHumanOnlyWritePath(target)) {
    return policy("review", `security-sensitive configuration write requires explicit approval: ${rawPath}`, {
      autoReview: false,
      humanOnly: true,
      details: { target },
    });
  }

  if (isTempPath(target)) {
    return policy("allow", `${request.toolName} writes to a temporary directory`, {
      details: { target },
    });
  }

  const extraRoot = extraWritableRoots().find((root) => isInside(root, target));
  if (extraRoot) {
    return policy("review", `${request.toolName} writes to an explicitly writable user configuration root`, {
      autoReview: true,
      details: { target, root: extraRoot },
    });
  }

  if (sessionRoot === home) {
    if (isDirectChild(home, target)) {
      return policy("allow", `${request.toolName} writes a file directly under the home directory`, {
        details: { target },
      });
    }

    return policy("review", `${request.toolName} writes below the home directory outside an approved root`, {
      autoReview: false,
      humanOnly: true,
      details: { target },
    });
  }

  if (isInside(sessionRoot, target)) {
    return policy("allow", `${request.toolName} writes inside the current workspace`, {
      details: { target },
    });
  }

  return policy("review", `${request.toolName} writes outside the current workspace`, {
    autoReview: false,
    humanOnly: true,
    details: { target },
  });
}

function bashAnalysis(
  analyses: readonly PermissionAnalyzerResult[],
): BashStructuralAnalysis | undefined {
  for (const item of analyses) {
    if (item.kind !== "bash" || !isRecord(item.data)) continue;
    const data = item.data as Partial<BashStructuralAnalysis>;
    if (typeof data.raw === "string" && Array.isArray(data.commands)) {
      return data as BashStructuralAnalysis;
    }
  }
  return undefined;
}

function commandPathCandidates(command: BashCommandNode, cwd: string): string[] {
  const candidates: string[] = [];
  for (const value of [...command.argv.slice(1), ...command.redirects.map((item) => item.target ?? "")]) {
    if (!value) continue;
    if (
      value === "~" ||
      value.startsWith("~/") ||
      value.startsWith("/") ||
      value.startsWith("./") ||
      value.startsWith("../") ||
      value.startsWith(".ssh/") ||
      value.startsWith(".aws/") ||
      value.startsWith(".gnupg/") ||
      value.startsWith(".pi/") ||
      value.startsWith(".codex/")
    ) {
      candidates.push(expandPath(value, cwd));
    }
  }
  return candidates;
}


function commandMayWrite(command: BashCommandNode): boolean {
  const name = command.argv[0] ?? "";
  if (command.redirects.length > 0) return true;
  if ([
    "rm",
    "rmdir",
    "mv",
    "cp",
    "mkdir",
    "touch",
    "install",
    "ln",
    "chmod",
    "chown",
    "chgrp",
    "tee",
    "truncate",
  ].includes(name)) {
    return true;
  }
  if (name === "sed" && command.argv.some((arg) => arg === "-i" || arg.startsWith("-i"))) {
    return true;
  }
  if (name === "perl" && command.argv.some((arg) => /^-[A-Za-z]*i[A-Za-z]*$/.test(arg))) {
    return true;
  }
  return false;
}

function isSafeGitCommand(argv: string[]): boolean {
  if (argv[0] !== "git") return false;
  const subcommand = argv[1] ?? "";
  if (["status", "diff", "log", "show", "rev-parse", "ls-files"].includes(subcommand)) {
    return true;
  }
  if (subcommand === "branch") {
    const mutation = argv.slice(2).some((arg) =>
      /^(?:-[dDmMcC]|--delete|--move|--copy|--edit-description|--set-upstream-to)(?:$|=)/.test(arg),
    );
    return !mutation;
  }
  return false;
}

function isSafeTestCommand(argv: string[]): boolean {
  const command = argv[0] ?? "";
  const sub = argv[1] ?? "";

  if (command === "pytest") return true;
  if (command === "python" && sub === "-m" && argv[2] === "pytest") return true;
  if (["ruff", "mypy", "tsc"].includes(command)) return true;
  if (command === "go" && ["test", "vet"].includes(sub)) return true;
  if (command === "cargo" && ["test", "check", "clippy"].includes(sub)) return true;
  if (command === "cargo" && sub === "fmt" && argv.includes("--check")) return true;

  if (["bun", "npm", "pnpm", "yarn"].includes(command)) {
    if (sub === "test") return true;
    if (sub === "run") {
      const script = argv[2] ?? "";
      return ["test", "lint", "typecheck", "check"].includes(script);
    }
  }

  if ((command === "npx" || command === "bunx") && argv[1] === "tsc") return true;
  return false;
}

function classifyBashCommand(argv: string[]): "safe" | "review" | "human" {
  const command = argv[0] ?? "";
  if (!command) return "review";
  if (HUMAN_ONLY_COMMANDS.has(command)) return "human";
  if (command === "find") {
    return argv.some((arg) => ["-delete", "-exec", "-execdir", "-ok", "-okdir"].includes(arg))
      ? "review"
      : "safe";
  }
  if (SAFE_SIMPLE_COMMANDS.has(command)) return "safe";
  if (isSafeGitCommand(argv) || isSafeTestCommand(argv)) return "safe";
  if (REVIEW_COMMANDS.has(command)) return "review";

  if (command === "git") return "review";
  if (["npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "brew"].includes(command)) {
    return "review";
  }
  if (["sed", "perl", "awk", "python", "python3", "node", "ruby", "sh", "bash", "zsh"].includes(command)) {
    return "review";
  }

  return "review";
}

function evaluateBash(
  request: PermissionRequest,
  analyses: readonly PermissionAnalyzerResult[],
): PermissionPolicyResult {
  const raw = typeof request.input.command === "string" ? request.input.command.trim() : "";
  if (!raw) {
    return policy("review", "bash command is missing or empty", {
      autoReview: false,
      humanOnly: true,
    });
  }

  for (const [pattern, reason] of HARD_DENY_COMMAND_PATTERNS) {
    if (pattern.test(raw)) {
      return policy("deny", `blocked dangerous shell operation: ${reason}`, {
        autoReview: false,
        humanOnly: false,
      });
    }
  }

  if (/(?:^|[\s'"])(?:~\/|\$HOME\/)?\.(?:ssh|aws|gnupg)(?:\/|[\s'"]|$)/i.test(raw) ||
      /(?:~\/|\$HOME\/)?\.(?:pi\/agent|codex)\/auth\.json/i.test(raw)) {
    return policy("review", "bash command references credential material", {
      autoReview: false,
      humanOnly: true,
    });
  }

  const structural = bashAnalysis(analyses);
  if (!structural) {
    return policy("review", "bash analyzer is unavailable; require review", {
      autoReview: true,
    });
  }

  for (const command of structural.commands) {
    for (const target of commandPathCandidates(command, request.cwd)) {
      if (isCredentialPath(target)) {
        return policy("review", "bash command references a credential path", {
          autoReview: false,
          humanOnly: true,
          details: { target },
        });
      }
      if (isHumanOnlyWritePath(target) && commandMayWrite(command)) {
        return policy("review", "bash command may modify security-sensitive configuration", {
          autoReview: false,
          humanOnly: true,
          details: { target },
        });
      }
    }
  }

  if (structural.dynamic || structural.warnings.length > 0) {
    return policy("review", "dynamic or incompletely parsed shell syntax requires review", {
      autoReview: true,
      details: {
        dynamic: structural.dynamic,
        warnings: structural.warnings,
      },
    });
  }

  if (structural.background) {
    return policy("review", "background process execution requires review", {
      autoReview: true,
    });
  }

  if (structural.commands.some((command) => command.redirects.length > 0)) {
    return policy("review", "shell redirection may modify files", {
      autoReview: true,
    });
  }

  let sawReview = false;
  for (const command of structural.commands) {
    const classification = classifyBashCommand(command.argv);
    if (classification === "human") {
      return policy("review", `privileged shell command requires explicit approval: ${command.argv[0]}`, {
        autoReview: false,
        humanOnly: true,
      });
    }
    if (classification === "review") sawReview = true;
  }

  if (!sawReview && structural.commands.length > 0) {
    return policy("allow", "all parsed shell commands are recognized as low-risk local operations");
  }

  return policy("review", "shell command has side effects or is not on the low-risk allowlist", {
    autoReview: true,
  });
}

function evaluatePolicy(
  request: PermissionRequest,
  analyses: readonly PermissionAnalyzerResult[],
): PermissionPolicyResult {
  if (request.toolName === "bash") return evaluateBash(request, analyses);
  if (BUILTIN_READ_TOOLS.has(request.toolName)) return evaluateReadTool(request);
  if (BUILTIN_WRITE_TOOLS.has(request.toolName)) return evaluateWriteTool(request);

  if (isKnownReadOnlyCustomTool(request.toolName)) {
    return policy("allow", `known read-only tool: ${request.toolName}`);
  }

  // Unknown/custom/MCP tools are intentionally reviewed. The reviewer may only
  // auto-approve when Codex classifies the concrete call as low risk.
  return policy("review", `custom or external tool requires review: ${request.toolName}`, {
    autoReview: true,
  });
}

function summarizeInput(input: Record<string, unknown>, maxLength = 2_000): string {
  let text: string;
  try {
    text = JSON.stringify(input, null, 2);
  } catch {
    text = String(input);
  }
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}\n…`;
}

function summarizeAnalyses(analyses: readonly PermissionAnalyzerResult[]): string {
  if (analyses.length === 0) return "none";
  return analyses
    .map((item) => {
      const warnings = item.warnings?.length ? ` warnings=${item.warnings.join("; ")}` : "";
      return `${item.analyzer}:${item.kind}${warnings}`;
    })
    .join("\n");
}

async function askHuman(
  request: PermissionRequest,
  policyResult: PermissionPolicyResult,
  analyses: readonly PermissionAnalyzerResult[],
  reviews: readonly PermissionReview[],
  ctx: ExtensionContext,
): Promise<boolean> {
  if (!ctx.hasUI) return false;

  const reviewText = reviews.length
    ? `\n\nReviewer:\n${reviews.map((item) => `[${item.reviewer}] ${item.reason}`).join("\n")}`
    : "";

  const prompt = [
    `Permission required: ${request.toolName}`,
    "",
    policyResult.reason,
    "",
    summarizeInput(request.input),
    "",
    `Analyzers:\n${summarizeAnalyses(analyses)}`,
    reviewText,
  ].join("\n");

  const choice = await ctx.ui.select(prompt, ["Allow once", "Block"]);
  return choice === "Allow once";
}

export default function piPermission(pi: ExtensionAPI) {
  const analyzers = new Map<string, PermissionAnalyzer>();
  const reviewers = new Map<string, PermissionReviewer>();

  pi.events.on(PERMISSION_EVENTS.registerAnalyzer, (data) => {
    if (!isAnalyzerRegistration(data)) return;
    analyzers.set(data.analyzer.id, data.analyzer);
  });

  pi.events.on(PERMISSION_EVENTS.registerReviewer, (data) => {
    if (!isReviewerRegistration(data)) return;
    reviewers.set(data.reviewer.id, data.reviewer);
  });

  const discover = () => {
    pi.events.emit(PERMISSION_EVENTS.discover, {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
    });
  };

  queueMicrotask(discover);
  pi.on("session_start", async () => {
    discover();
  });

  pi.registerCommand("permission", {
    description: "Show pi-permission adapter status",
    handler: async (_args, ctx) => {
      const analyzerList =
        sortByPriority(analyzers.values()).map((item) => item.id).join(", ") || "none";
      const reviewerList =
        sortByPriority(reviewers.values()).map((item) => item.id).join(", ") || "none";
      ctx.ui.notify(
        `pi-permission\nanalyzers: ${analyzerList}\nreviewers: ${reviewerList}`,
        "info",
      );
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    const request = normalizeRequest(event, ctx);
    const analyses: PermissionAnalyzerResult[] = [];

    for (const analyzer of sortByPriority(analyzers.values())) {
      if (!analyzer.supports(request)) continue;
      try {
        const result = await analyzer.analyze(request, ctx);
        if (result) analyses.push(result);
      } catch (error) {
        analyses.push({
          analyzer: analyzer.id,
          kind: "error",
          data: {},
          warnings: [error instanceof Error ? error.message : String(error)],
        });
      }
    }

    const policyResult = evaluatePolicy(request, analyses);

    if (policyResult.decision === "allow") return undefined;

    if (policyResult.decision === "deny") {
      if (ctx.hasUI) {
        ctx.ui.notify(`Blocked by pi-permission: ${policyResult.reason}`, "warning");
      }
      return { block: true, reason: policyResult.reason };
    }

    const reviews: PermissionReview[] = [];

    if (policyResult.autoReview && !policyResult.humanOnly) {
      for (const reviewer of sortByPriority(reviewers.values())) {
        try {
          const result = await reviewer.review(request, policyResult, analyses, ctx);
          reviews.push(result);
          if (result.decision === "allow") return undefined;
        } catch (error) {
          reviews.push({
            reviewer: reviewer.id,
            decision: "defer",
            reason: `Reviewer failed: ${error instanceof Error ? error.message : String(error)}`,
          });
        }
      }
    }

    const allowed = await askHuman(request, policyResult, analyses, reviews, ctx);
    if (allowed) return undefined;

    return {
      block: true,
      reason: ctx.hasUI
        ? "Blocked by user"
        : `Permission required but no interactive UI is available: ${policyResult.reason}`,
    };
  });
}
