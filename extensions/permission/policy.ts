import { accessSync, constants } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, resolve } from "node:path";

import {
  BASH_ANALYSIS_KIND,
  TREE_SITTER_BASH_PLUGIN_ID,
  type BashCommand,
  type BashStaticWord,
  type BashTreeSitterAnalysis,
} from "../permission-tree-sitter-bash/types.ts";
import {
  createPathPolicyContext,
  isInside,
  isCredentialPath,
  isDefaultSandboxWritable,
  isTempPath,
  protectedRootForPath,
  resolveBashPathIdentity,
  resolveToolPathIdentity,
  type PathIdentity,
  type PathPolicyContext,
} from "./paths.ts";
import type {
  PermissionAnalysis,
  PermissionPolicyResult,
  PermissionRequest,
} from "./protocol.ts";
import {
  matchBashPermissionRule,
  matchPermissionRule,
  type PermissionRule,
} from "./rules.ts";

const BUILTIN_READ_TOOLS = new Set(["read", "grep", "find", "ls"]);
const BUILTIN_WRITE_TOOLS = new Set(["write", "edit"]);
const KNOWN_SELF_ENFORCING_TOOLS = new Set(["trash"]);
const SAFE_BASH_COMMANDS = new Set([
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
const PRIVILEGED_COMMANDS = new Set(["sudo", "doas", "su"]);

function allow(ruleId: string, reason: string, details?: Record<string, unknown>): PermissionPolicyResult {
  return { decision: "allow", ruleId, reason, details };
}

function deny(ruleId: string, reason: string, details?: Record<string, unknown>): PermissionPolicyResult {
  return { decision: "deny", ruleId, reason, details };
}

function review(
  ruleId: string,
  reason: string,
  route: "model-then-human" | "human" = "model-then-human",
  details?: Record<string, unknown>,
): PermissionPolicyResult {
  return { decision: "review", ruleId, reason, route, details };
}

function bashAnalysis(
  analyses: readonly PermissionAnalysis[],
): BashTreeSitterAnalysis | undefined {
  const analysis = analyses.find(
    (item) =>
      item.analyzer === TREE_SITTER_BASH_PLUGIN_ID &&
      item.kind === BASH_ANALYSIS_KIND,
  )?.data;
  if (!analysis || typeof analysis !== "object") return undefined;
  const value = analysis as Partial<BashTreeSitterAnalysis>;
  return typeof value.raw === "string" && Array.isArray(value.commands)
    ? value as BashTreeSitterAnalysis
    : undefined;
}

function pathFromInput(input: Record<string, unknown>): string | undefined {
  for (const key of ["path", "file", "filePath", "file_path", "target"]) {
    const value = input[key];
    if (typeof value === "string" && value.trim() !== "") return value;
  }
  return undefined;
}

const SHELL_BUILTINS = new Set(["pwd", "echo", "printf", "true", "false", "test", "[", "cd"]);
const TRUSTED_EXECUTABLE_DIRS = [
  "/bin", "/usr/bin", "/sbin", "/usr/sbin", "/opt/homebrew/bin", "/usr/local/bin",
].map((path) => resolve(path));

function commandName(command: BashCommand): string {
  return command.resolvedArgv?.[0] ?? "";
}

function trustedCommandName(
  command: BashCommand,
  cache: Map<string, string | undefined>,
): string | undefined {
  const executable = commandName(command);
  if (!executable) return undefined;
  if (cache.has(executable)) return cache.get(executable);

  let trusted: string | undefined;
  if (SHELL_BUILTINS.has(executable)) {
    trusted = executable;
  } else {
    let path: string | undefined;
    if (executable.includes("/")) {
      if (isAbsolute(executable)) path = resolve(executable);
    } else {
      for (const entry of (process.env.PATH ?? "").split(delimiter)) {
        if (!entry) continue;
        const candidate = resolve(entry, executable);
        try {
          accessSync(candidate, constants.X_OK);
          path = candidate;
          break;
        } catch {
          // Continue PATH lookup.
        }
      }
    }
    trusted = path && TRUSTED_EXECUTABLE_DIRS.includes(dirname(path))
      ? basename(path)
      : undefined;
  }

  cache.set(executable, trusted);
  return trusted;
}

const CREDENTIAL_MARKER = /(?:^|[\s'"=])(?:~\/|\$HOME\/|\$\{HOME\}\/)?\.(?:ssh|aws|gnupg)(?:\/|[\s'"=]|$)|(?:^|[\s'"=])(?:~\/|\$HOME\/|\$\{HOME\}\/)?\.(?:netrc|npmrc|pypirc|git-credentials)(?:[\s'"=]|$)|(?:~\/|\$HOME\/|\$\{HOME\}\/)?\.docker\/config\.json|(?:~\/|\$HOME\/|\$\{HOME\}\/)?\.config\/(?:gh\/hosts\.yml|gcloud\/application_default_credentials\.json)|(?:\.pi\/agent|\.codex)\/auth\.json/i;
const ATTACHED_SHORT_PATH_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  file: ["-f", "-m"],
  grep: ["-f"],
  rg: ["-f"],
};

function pathWord(value: string, quoted: boolean): BashStaticWord {
  return {
    raw: value,
    value,
    quoted,
    expandTilde: !quoted && (value === "~" || value.startsWith("~/")),
  };
}

function credentialPathWords(command: BashCommand): BashStaticWord[] {
  const arguments_ = command.words.slice(1);
  const candidates = [
    ...arguments_.filter((word) => !word.value?.startsWith("-")),
    ...command.redirects.flatMap((redirect) => redirect.target ? [redirect.target] : []),
  ];
  const shortOptions = ATTACHED_SHORT_PATH_OPTIONS[basename(commandName(command))] ?? [];

  for (const word of arguments_) {
    const value = word.value;
    if (!value?.startsWith("-")) continue;

    const equals = value.indexOf("=");
    if (equals >= 0 && equals + 1 < value.length) {
      candidates.push(pathWord(value.slice(equals + 1), word.quoted));
    }
    for (const option of shortOptions) {
      if (value.startsWith(option) && value.length > option.length) {
        candidates.push(pathWord(value.slice(option.length), word.quoted));
      }
    }
  }

  return candidates;
}

async function credentialReference(
  analysis: BashTreeSitterAnalysis,
  paths: PathPolicyContext,
): Promise<PathIdentity | undefined> {
  for (const command of analysis.commands) {
    for (const word of credentialPathWords(command)) {
      if (!word.value) continue;
      try {
        const target = await resolveBashPathIdentity(word, paths.cwd);
        if (isCredentialPath(target, paths)) return target;
      } catch {
        if (CREDENTIAL_MARKER.test(word.raw)) {
          return { logical: word.raw, canonical: word.raw };
        }
      }
    }
  }
  return CREDENTIAL_MARKER.test(analysis.raw)
    ? { logical: "dynamic credential path", canonical: "dynamic credential path" }
    : undefined;
}

async function rootDeletion(
  command: BashCommand,
  paths: PathPolicyContext,
  trustedCommands: Map<string, string | undefined>,
): Promise<boolean> {
  if (trustedCommandName(command, trustedCommands) !== "rm") return false;
  const argv = command.resolvedArgv;
  if (!argv) return false;
  const recursive = argv.slice(1).some((arg) => arg === "--recursive" || /^-[^-]*[rR]/.test(arg));
  const forced = argv.slice(1).some((arg) => arg === "--force" || /^-[^-]*f/.test(arg));
  if (!recursive || !forced) return false;

  const home = await paths.homeIdentity();
  for (const word of command.words.slice(1)) {
    if (!word.value || word.value.startsWith("-")) continue;
    try {
      const target = await resolveBashPathIdentity(word, paths.cwd);
      if (target.canonical === resolve("/") || target.canonical === home.canonical) return true;
    } catch {
      // Dynamic targets are handled by the normal review path.
    }
  }
  return false;
}

async function hardDeniedCommand(
  commands: readonly BashCommand[],
  paths: PathPolicyContext,
  trustedCommands: Map<string, string | undefined>,
): Promise<string | undefined> {
  for (const command of commands) {
    const argv = command.resolvedArgv;
    if (!argv) continue;
    const name = trustedCommandName(command, trustedCommands) ?? "";
    if (await rootDeletion(command, paths, trustedCommands)) {
      return "recursive forced deletion of the filesystem or home root";
    }
    if (/^(?:mkfs(?:\.[a-z0-9]+)?|newfs(?:_[a-z0-9]+)?)$/i.test(name)) {
      return "filesystem formatting";
    }
    if (name === "diskutil") {
      if (["eraseDisk", "eraseVolume", "partitionDisk"].includes(argv[1] ?? "")) {
        return "disk erase or partition operation";
      }
      if (argv[1] === "apfs" && argv[2] === "deleteContainer") {
        return "APFS container deletion";
      }
    }
    if (name === "dd" && argv.slice(1).some((arg) => /^of=\/dev\//.test(arg))) {
      return "raw device write";
    }
  }
  return undefined;
}

async function assessBashWriteTargets(
  analysis: BashTreeSitterAnalysis,
  paths: PathPolicyContext,
): Promise<{
  targets: Array<Record<string, unknown>>;
  outsideSandbox: boolean;
  protected: boolean;
  credential: boolean;
}> {
  const targets: Array<Record<string, unknown>> = [];
  let outsideSandbox = false;
  let protectedPath = false;
  let credential = false;

  for (const target of analysis.writeTargets) {
    const identity = await resolveBashPathIdentity(target.path, paths.cwd);
    const protectedRoot = protectedRootForPath(identity, paths);
    const credentialPath = isCredentialPath(identity, paths);
    const defaultWritable = await isDefaultSandboxWritable(identity, paths);
    outsideSandbox ||= !defaultWritable;
    protectedPath ||= protectedRoot !== undefined;
    credential ||= credentialPath;
    targets.push({
      raw: target.path.raw,
      path: identity.logical,
      canonicalPath: identity.canonical,
      mode: target.mode,
      operation: target.operation,
      defaultWritable,
      protectedRoot: protectedRoot?.id,
      credential: credentialPath,
    });
  }

  return { targets, outsideSandbox, protected: protectedPath, credential };
}

function isBashDeletion(
  command: BashCommand,
  trustedCommands: Map<string, string | undefined>,
): boolean {
  const name = trustedCommandName(command, trustedCommands);
  const argv = command.resolvedArgv ?? [];
  return (
    name === "rm" ||
    name === "rmdir" ||
    name === "unlink" ||
    name === "shred" ||
    (name === "find" && argv.includes("-delete")) ||
    (name === "git" && argv[1] === "clean")
  );
}

function isDeterministicSafeBashCommand(
  command: BashCommand,
  trustedCommands: Map<string, string | undefined>,
): boolean {
  const name = trustedCommandName(command, trustedCommands);
  return (
    command.effectsComplete === true &&
    name !== undefined &&
    SAFE_BASH_COMMANDS.has(name)
  );
}

async function evaluateReadTool(request: PermissionRequest): Promise<PermissionPolicyResult> {
  // grep, find, and ls use cwd when path is omitted, so assess that effective target too.
  const rawPath = pathFromInput(request.input) ?? request.cwd;
  const paths = createPathPolicyContext(request.cwd);

  let target: PathIdentity;
  try {
    target = await resolveToolPathIdentity(rawPath, request.cwd);
  } catch (error) {
    return review(
      "read-path-unresolved",
      `read target could not be resolved safely: ${rawPath}`,
      "human",
      { error: error instanceof Error ? error.message : String(error) },
    );
  }
  if (isCredentialPath(target, paths)) {
    return review(
      "credential-read",
      `credential path access requires explicit approval: ${rawPath}`,
      "human",
      { target: target.logical, canonicalTarget: target.canonical },
    );
  }
  return allow("builtin-read", `${request.toolName} is read-only`, {
    target: target.logical,
    canonicalTarget: target.canonical,
  });
}

async function evaluateWriteTool(request: PermissionRequest): Promise<PermissionPolicyResult> {
  const rawPath = pathFromInput(request.input);
  if (!rawPath) {
    return review("write-path-missing", `${request.toolName} has no usable target path`, "human");
  }
  const paths = createPathPolicyContext(request.cwd);

  let target: PathIdentity;
  try {
    target = await resolveToolPathIdentity(rawPath, request.cwd);
  } catch (error) {
    return review(
      "write-path-unresolved",
      `write target could not be resolved safely: ${rawPath}`,
      "human",
      { error: error instanceof Error ? error.message : String(error) },
    );
  }

  if (isCredentialPath(target, paths)) {
    return review(
      "credential-write",
      `credential modification requires explicit approval: ${rawPath}`,
      "human",
      { target: target.logical, canonicalTarget: target.canonical },
    );
  }
  const protectedRoot = protectedRootForPath(target, paths);
  if (protectedRoot) {
    return review(
      "protected-config-write",
      `Pi or Codex configuration write requires review: ${rawPath}`,
      "model-then-human",
      {
        target: target.logical,
        canonicalTarget: target.canonical,
        protectedRoot: protectedRoot.id,
      },
    );
  }
  if (isTempPath(target, paths)) {
    return allow("temporary-write", `${request.toolName} writes to a temporary directory`, {
      target: target.logical,
      canonicalTarget: target.canonical,
    });
  }

  const workspace = await paths.workspaceIdentity();
  const home = await paths.homeIdentity();
  if (
    workspace.canonical !== home.canonical &&
    isInside(workspace.canonical, target.canonical)
  ) {
    return allow("workspace-write", `${request.toolName} writes inside the current workspace`, {
      target: target.logical,
      canonicalTarget: target.canonical,
    });
  }
  return review(
    "outside-workspace-write",
    `${request.toolName} writes outside the current workspace`,
    "model-then-human",
    { target: target.logical, canonicalTarget: target.canonical },
  );
}

async function evaluateBash(
  request: PermissionRequest,
  analysis: BashTreeSitterAnalysis | undefined,
  configuredRules: readonly PermissionRule[],
): Promise<PermissionPolicyResult> {
  const command = typeof request.input.command === "string" ? request.input.command.trim() : "";
  if (!command) return review("bash-command-missing", "bash command is missing or empty", "human");
  if (!analysis || analysis.raw !== request.input.command) {
    return review("bash-analyzer-unavailable", "Bash analyzer is unavailable or stale", "human");
  }

  const paths = createPathPolicyContext(request.cwd);
  const trustedCommands = new Map<string, string | undefined>();
  const hardDeny = await hardDeniedCommand(
    analysis.commands,
    paths,
    trustedCommands,
  );
  if (hardDeny) return deny("dangerous-shell-operation", `blocked dangerous shell operation: ${hardDeny}`);

  if (analysis.commands.some((commandNode) =>
    isBashDeletion(commandNode, trustedCommands)
  )) {
    return deny(
      "bash-deletion-disallowed",
      "Bash deletion is disabled; use the trash tool so the operation remains recoverable",
    );
  }

  const credential = await credentialReference(analysis, paths);
  if (credential) {
    return review(
      "credential-shell-access",
      "bash command references credential material",
      "human",
      { target: credential.logical, canonicalTarget: credential.canonical },
    );
  }

  let writeAssessment;
  try {
    writeAssessment = await assessBashWriteTargets(analysis, paths);
  } catch (error) {
    return review(
      "bash-write-target-unresolved",
      "Bash write target could not be resolved safely",
      "human",
      { error: error instanceof Error ? error.message : String(error) },
    );
  }

  if (writeAssessment.credential) {
    return deny(
      "bash-credential-write-disallowed",
      "Bash cannot modify credential material; use write or edit with explicit human approval",
      { targets: writeAssessment.targets },
    );
  }
  if (writeAssessment.protected || writeAssessment.outsideSandbox) {
    return deny(
      writeAssessment.protected
        ? "bash-protected-write-disallowed"
        : "bash-outside-sandbox-write-disallowed",
      writeAssessment.protected
        ? "Bash cannot write to Pi or Codex configuration; use write or edit instead"
        : "Bash cannot write outside the workspace or temporary directories; use write or edit instead",
      { targets: writeAssessment.targets },
    );
  }

  for (const commandNode of analysis.commands) {
    if (PRIVILEGED_COMMANDS.has(
      trustedCommandName(commandNode, trustedCommands) ?? "",
    )) {
      return review(
        "privileged-shell-command",
        `privileged shell command requires explicit approval: ${commandName(commandNode)}`,
        "human",
      );
    }
  }

  const staticallyComposable =
    analysis.complete &&
    !analysis.dynamic &&
    !analysis.opaque &&
    !analysis.background &&
    analysis.commands.length > 0;
  if (staticallyComposable) {
    const configuredResults: PermissionPolicyResult[] = [];
    let hasUnmatchedCommand = false;

    for (const commandNode of analysis.commands) {
      const configured = commandNode.resolvedArgv
        ? configuredBashRulePolicy(commandNode.resolvedArgv, configuredRules)
        : undefined;
      if (configured) {
        configuredResults.push(configured);
      } else if (!isDeterministicSafeBashCommand(commandNode, trustedCommands)) {
        hasUnmatchedCommand = true;
      }
    }

    const configuredDeny = configuredResults.find((result) => result.decision === "deny");
    if (configuredDeny) return configuredDeny;
    const configuredHumanReview = configuredResults.find(
      (result) => result.decision === "review" && result.route === "human",
    );
    if (configuredHumanReview) return configuredHumanReview;
    const configuredModelReview = configuredResults.find(
      (result) => result.decision === "review",
    );
    if (configuredModelReview) return configuredModelReview;

    if (!hasUnmatchedCommand) {
      if (analysis.commands.length === 1 && configuredResults.length === 1) {
        return configuredResults[0]!;
      }
      const commandPrefixes = [...new Set(configuredResults.flatMap((result) => {
        const prefix = result.details?.commandPrefix;
        return result.decision === "allow" && typeof prefix === "string" ? [prefix] : [];
      }))];
      if (commandPrefixes.length > 0) {
        return allow(
          "configured-tool-rule",
          "all commands in the static shell composition are allowed by configured or deterministic rules",
          {
            commandPrefixes,
            controlOperators: analysis.controlOperators ?? [],
            targets: writeAssessment.targets,
          },
        );
      }
      return allow(
        "safe-static-shell",
        "all shell commands are static, local, and recognized as low risk",
        {
          controlOperators: analysis.controlOperators ?? [],
          targets: writeAssessment.targets,
        },
      );
    }
  }

  if (
    !analysis.complete ||
    analysis.dynamic ||
    analysis.opaque ||
    analysis.background
  ) {
    return review(
      "complex-shell-command",
      "dynamic, opaque, background, or incompletely analyzed shell syntax requires review",
      "model-then-human",
      {
        complete: analysis.complete,
        dynamic: analysis.dynamic,
        opaque: analysis.opaque,
        background: analysis.background,
        controlOperators: analysis.controlOperators ?? [],
        warnings: analysis.warnings,
      },
    );
  }

  return review(
    "unrecognized-shell-command",
    analysis.writeTargetsComplete
      ? "shell command is not on the deterministic low-risk allowlist"
      : "shell command effects are not completely modeled by the deterministic policy",
    "model-then-human",
    {
      controlOperators: analysis.controlOperators ?? [],
      targets: writeAssessment.targets,
      writeTargetsComplete: analysis.writeTargetsComplete,
    },
  );
}

function configuredBashRulePolicy(
  argv: readonly string[],
  rules: readonly PermissionRule[],
): PermissionPolicyResult | undefined {
  const match = matchBashPermissionRule(argv, rules);
  if (!match?.commandPrefix) return undefined;
  const prefix = match.commandPrefix.join(" ");
  const reason = `permission.json command prefix rule for bash: ${prefix}`;
  const details = { commandPrefix: prefix };
  switch (match.rule.decision) {
    case "allow": return allow("configured-tool-rule", reason, details);
    case "review": return review("configured-tool-rule", reason, "model-then-human", details);
    case "human": return review("configured-tool-rule", reason, "human", details);
    case "deny": return deny("configured-tool-rule", reason, details);
  }
}

function configuredRulePolicy(
  request: PermissionRequest,
  rules: readonly PermissionRule[],
): PermissionPolicyResult | undefined {
  const match = matchPermissionRule(request, rules);
  if (!match) return undefined;
  const suffix = match.action ? ` action ${match.action}` : "";
  const reason = `permission.json rule for ${request.toolName}${suffix}`;
  switch (match.rule.decision) {
    case "allow": return allow("configured-tool-rule", reason);
    case "review": return review("configured-tool-rule", reason, "model-then-human");
    case "human": return review("configured-tool-rule", reason, "human");
    case "deny": return deny("configured-tool-rule", reason);
  }
}

async function genericCredentialPolicy(
  request: PermissionRequest,
): Promise<PermissionPolicyResult | undefined> {
  const rawPath = pathFromInput(request.input);
  if (!rawPath) return undefined;
  const paths = createPathPolicyContext(request.cwd);
  try {
    const path = await resolveToolPathIdentity(rawPath, request.cwd);
    return isCredentialPath(path, paths)
      ? review(
          "credential-external-tool",
          `external tool references credential material: ${rawPath}`,
          "human",
          { target: path.logical },
        )
      : undefined;
  } catch (error) {
    return review(
      "external-tool-path-unresolved",
      `external tool path could not be resolved safely: ${rawPath}`,
      "human",
      { error: error instanceof Error ? error.message : String(error) },
    );
  }
}

export async function evaluatePolicy(
  request: PermissionRequest,
  analyses: readonly PermissionAnalysis[],
  configuredRules: readonly PermissionRule[] = [],
): Promise<PermissionPolicyResult> {
  if (request.toolName === "bash") {
    return evaluateBash(request, bashAnalysis(analyses), configuredRules);
  }
  if (BUILTIN_READ_TOOLS.has(request.toolName)) return evaluateReadTool(request);
  if (BUILTIN_WRITE_TOOLS.has(request.toolName)) return evaluateWriteTool(request);
  const credentialPolicy = await genericCredentialPolicy(request);
  if (credentialPolicy) return credentialPolicy;
  const configured = configuredRulePolicy(request, configuredRules);
  if (configured) return configured;
  if (KNOWN_SELF_ENFORCING_TOOLS.has(request.toolName)) {
    return allow("known-self-enforcing-tool", `tool enforces its own workspace boundary: ${request.toolName}`);
  }
  return review(
    "custom-tool",
    `custom or external tool requires review: ${request.toolName}`,
    "model-then-human",
  );
}
