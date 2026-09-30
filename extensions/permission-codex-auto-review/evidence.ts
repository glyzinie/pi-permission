import type {
  PermissionAnalysis,
  PermissionRequest,
  PermissionReviewPolicy,
} from "../permission/protocol.ts";
import {
  BASH_ANALYSIS_KIND,
  type BashTreeSitterAnalysis,
} from "../permission-tree-sitter-bash/types.ts";

const MAX_STRING = 8_000;
const MAX_ARRAY = 40;
const MAX_KEYS = 80;
const MAX_DEPTH = 6;
const MAX_PROJECTED_NODES = 2_000;
const MAX_EVIDENCE_BYTES = 32_000;
const OMITTED = "[omitted]";
const SECRET_KEY = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)/i;
const SECRET_TEXT = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]+|(?:^|[\s;&])(?:[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY))\s*=\s*[^\s;&]+|["']?(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)["']?\s*:\s*["'][^"']+["']|\bsk-[A-Za-z0-9_-]{16,}|https?:\/\/[^\s/:]+:[^\s/@]+@/im;

interface ProjectionState {
  unsafe: boolean;
  exhausted: boolean;
  nodes: number;
  bytes: number;
  seen: WeakSet<object>;
}

function reserve(
  state: ProjectionState,
  key: string,
  text = "",
): boolean {
  if (state.exhausted) return false;
  state.nodes += 1;
  state.bytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(text, "utf8");
  if (state.nodes <= MAX_PROJECTED_NODES && state.bytes <= MAX_EVIDENCE_BYTES) {
    return true;
  }
  state.unsafe = true;
  state.exhausted = true;
  return false;
}

function projectValue(
  value: unknown,
  state: ProjectionState,
  depth = 0,
  key = "",
): unknown {
  if (state.exhausted) return OMITTED;
  if (key.length > MAX_STRING) {
    state.unsafe = true;
    state.exhausted = true;
    return OMITTED;
  }
  if (SECRET_KEY.test(key)) {
    state.unsafe = true;
    return reserve(state, key, "[redacted]") ? "[redacted]" : OMITTED;
  }
  if (typeof value === "string") {
    const truncated = value.length > MAX_STRING;
    const candidate = truncated ? value.slice(0, MAX_STRING) : value;
    if (truncated) state.unsafe = true;
    if (SECRET_TEXT.test(candidate)) {
      state.unsafe = true;
      const redacted = "[redacted secret-bearing string]";
      return reserve(state, key, redacted) ? redacted : OMITTED;
    }
    const projected = truncated ? `${candidate}…` : candidate;
    return reserve(state, key, projected) ? projected : OMITTED;
  }
  if (
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    state.unsafe = true;
    const unsupported = `[unsupported ${typeof value}]`;
    return reserve(state, key, unsupported) ? unsupported : OMITTED;
  }
  if (value === null || typeof value !== "object") {
    return reserve(state, key) ? value : OMITTED;
  }
  if (!reserve(state, key)) return OMITTED;
  if (depth >= MAX_DEPTH || state.seen.has(value)) {
    state.unsafe = true;
    return OMITTED;
  }

  state.seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_ARRAY) state.unsafe = true;
      const projected: unknown[] = [];
      const length = Math.min(value.length, MAX_ARRAY);
      for (let index = 0; index < length; index += 1) {
        projected.push(projectValue(value[index], state, depth + 1));
        if (state.exhausted) break;
      }
      return projected;
    }

    const projected = Object.create(null) as Record<string, unknown>;
    let count = 0;
    for (const entryKey in value as Record<string, unknown>) {
      if (!Object.hasOwn(value, entryKey)) continue;
      if (count >= MAX_KEYS) {
        state.unsafe = true;
        break;
      }
      count += 1;
      projected[entryKey] = projectValue(
        (value as Record<string, unknown>)[entryKey],
        state,
        depth + 1,
        entryKey,
      );
      if (state.exhausted) break;
    }
    return projected;
  } finally {
    state.seen.delete(value);
  }
}

function projectBashAnalysis(
  data: unknown,
  state: ProjectionState,
): unknown {
  if (!data || typeof data !== "object" || state.exhausted) return undefined;
  const analysis = data as Partial<BashTreeSitterAnalysis>;
  const commands = Array.isArray(analysis.commands)
    ? analysis.commands
    : undefined;
  if (commands && commands.length > MAX_ARRAY) state.unsafe = true;
  const selectedCommands = commands?.slice(0, MAX_ARRAY);

  let redirects: unknown[] | undefined;
  if (selectedCommands) {
    redirects = [];
    redirectLoop:
    for (const command of selectedCommands) {
      for (const redirect of command.redirects) {
        if (redirects.length >= MAX_ARRAY) {
          state.unsafe = true;
          break redirectLoop;
        }
        redirects.push(redirect);
      }
    }
  }

  return {
    complete: analysis.complete,
    dynamic: analysis.dynamic,
    opaque: analysis.opaque,
    background: analysis.background,
    controlOperators: analysis.controlOperators,
    commands: selectedCommands?.map((command) => ({
      argv: command.resolvedArgv,
      effectsComplete: command.effectsComplete,
    })),
    redirects,
    writeTargets: analysis.writeTargets,
    writeTargetsComplete: analysis.writeTargetsComplete,
  };
}

export type ReviewEvidence =
  | { safeForAutoReview: false; value: unknown; serialized?: never }
  | {
      safeForAutoReview: true;
      value: unknown;
      /** Compact prompt-ready JSON for the model request. */
      serialized: string;
    };

export function buildReviewEvidence(
  request: PermissionRequest,
  policy: PermissionReviewPolicy,
  analyses: readonly PermissionAnalysis[],
): ReviewEvidence {
  const state: ProjectionState = {
    unsafe: false,
    exhausted: false,
    nodes: 0,
    bytes: 0,
    seen: new WeakSet(),
  };
  const projectedRequest = projectValue({
    toolName: request.toolName,
    ...(request.originalToolName !== request.toolName
      ? { originalToolName: request.originalToolName }
      : {}),
    source: request.source,
    cwd: request.cwd,
    input: request.input,
  }, state, -1, "request");
  const projectedPolicy = projectValue({
    ruleId: policy.ruleId,
    reason: policy.reason,
    details: policy.details,
  }, state, -1, "policy");

  if (analyses.length > MAX_ARRAY) state.unsafe = true;
  const projectedAnalyses: unknown[] = [];
  const analysisCount = Math.min(analyses.length, MAX_ARRAY);
  for (let index = 0; index < analysisCount; index += 1) {
    const analysis = analyses[index]!;
    const selected = {
      analyzer: analysis.analyzer,
      kind: analysis.kind,
      data: analysis.kind === BASH_ANALYSIS_KIND
        ? projectBashAnalysis(analysis.data, state)
        : undefined,
      warnings: analysis.warnings,
    };
    projectedAnalyses.push(projectValue(selected, state, -1, "analysis"));
    if (state.exhausted) break;
  }

  const value = {
    request: projectedRequest,
    policy: projectedPolicy,
    analyses: projectedAnalyses,
  };

  let serialized: string | undefined;
  if (!state.unsafe) {
    try {
      const candidate = JSON.stringify(value);
      if (Buffer.byteLength(candidate, "utf8") <= MAX_EVIDENCE_BYTES) {
        serialized = candidate;
      } else {
        state.unsafe = true;
      }
    } catch {
      state.unsafe = true;
    }
  }

  return state.unsafe || serialized === undefined
    ? { safeForAutoReview: false, value }
    : { safeForAutoReview: true, value, serialized };
}
