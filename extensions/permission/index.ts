import { join } from "node:path";

import {
  getAgentDir,
  type ExtensionAPI,
  type ExtensionContext,
  type ToolCallEvent,
} from "@earendil-works/pi-coding-agent";

import { evaluatePolicy } from "./policy.ts";
import {
  loadPermissionRules,
  type PermissionRule,
} from "./rules.ts";
import {
  localizedPolicyReason,
  localizedReviewReason,
  permissionLabels,
  type PermissionLanguage,
} from "./ui.ts";
import {
  PERMISSION_EVENTS,
  PERMISSION_PROTOCOL_VERSION,
  type PermissionAnalysis,
  type PermissionAnalyzer,
  type PermissionPolicyResult,
  type PermissionRequest,
  type PermissionReview,
  type PermissionReviewer,
  type RegisterAnalyzerEvent,
  type RegisterReviewerEvent,
} from "./protocol.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAnalyzerRegistration(value: unknown): value is RegisterAnalyzerEvent {
  if (!isRecord(value) || value.protocolVersion !== PERMISSION_PROTOCOL_VERSION) return false;
  const analyzer = value.analyzer;
  return (
    isRecord(analyzer) &&
    typeof analyzer.id === "string" && analyzer.id !== "" &&
    typeof analyzer.supports === "function" &&
    typeof analyzer.analyze === "function"
  );
}

function isReviewerRegistration(value: unknown): value is RegisterReviewerEvent {
  if (!isRecord(value) || value.protocolVersion !== PERMISSION_PROTOCOL_VERSION) return false;
  const reviewer = value.reviewer;
  return (
    isRecord(reviewer) &&
    typeof reviewer.id === "string" && reviewer.id !== "" &&
    typeof reviewer.review === "function"
  );
}

function byPriority<T extends { id: string; priority?: number }>(values: Iterable<T>): T[] {
  return [...values].sort((a, b) => {
    const priority = (b.priority ?? 0) - (a.priority ?? 0);
    return priority !== 0 ? priority : a.id.localeCompare(b.id);
  });
}

function immutableInput(value: Record<string, unknown>): Readonly<Record<string, unknown>> {
  const clone = structuredClone(value) as Record<string, unknown>;
  const stack: object[] = [clone];
  while (stack.length > 0) {
    const item = stack.pop()!;
    if (Object.isFrozen(item)) continue;
    Object.freeze(item);
    const children = Array.isArray(item) ? item : Object.values(item);
    for (const child of children) {
      if (child && typeof child === "object" && !Object.isFrozen(child)) stack.push(child);
    }
  }
  return clone;
}

function normalizeRequest(event: ToolCallEvent, ctx: ExtensionContext): PermissionRequest {
  const originalInput = isRecord(event.input) ? immutableInput(event.input) : {};
  if (event.toolName === "mcp" && typeof originalInput.tool === "string") {
    return Object.freeze({
      toolCallId: event.toolCallId,
      toolName: `mcp:${originalInput.tool}`,
      originalToolName: event.toolName,
      input: isRecord(originalInput.args) ? originalInput.args : originalInput,
      cwd: ctx.cwd,
      source: "mcp" as const,
    });
  }
  return Object.freeze({
    toolCallId: event.toolCallId,
    toolName: event.toolName,
    originalToolName: event.toolName,
    input: originalInput,
    cwd: ctx.cwd,
    source: "pi" as const,
  });
}

function summarize(value: unknown, maxLength: number): string {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}\n…`;
}

async function askHuman(
  request: PermissionRequest,
  policy: PermissionPolicyResult,
  analyses: readonly PermissionAnalysis[],
  reviews: readonly PermissionReview[],
  ctx: ExtensionContext,
  language: PermissionLanguage,
): Promise<boolean> {
  if (!ctx.hasUI) return false;
  const labels = permissionLabels(language);
  const analyzerText = analyses.length === 0
    ? language === "ja" ? "なし" : "none"
    : analyses.map((analysis) => {
        const warnings = analysis.warnings?.length
          ? ` warnings=${analysis.warnings.join("; ")}`
          : "";
        return `${analysis.analyzer}:${analysis.kind}${warnings}`;
      }).join("\n");
  const reviewerText = reviews.length === 0
    ? ""
    : `\n\n${labels.reviewer}:\n${reviews.map((review) =>
        `[${review.reviewer}] ${localizedReviewReason(review, language)}`,
      ).join("\n")}`;
  const inputLimit = 4_000;
  const prompt = [
    `${labels.title}: ${request.toolName}`,
    "",
    `${labels.reason}:`,
    localizedPolicyReason(policy, language),
    "",
    `${labels.input}:`,
    summarize(request.input, inputLimit),
    "",
    `${labels.analyzers}:\n${analyzerText}`,
    reviewerText,
  ].join("\n");
  return await ctx.ui.select(
    prompt,
    [labels.allowOnce, labels.block],
    { signal: ctx.signal },
  ) === labels.allowOnce;
}

export default function permissionExtension(pi: ExtensionAPI): void {
  const analyzers = new Map<string, PermissionAnalyzer>();
  const reviewers = new Map<string, PermissionReviewer>();
  const rulesPath = join(getAgentDir(), "permission.json");
  let configuredRules: readonly PermissionRule[] = [];
  let language: PermissionLanguage = "en";
  let rulesError: string | undefined;

  pi.events.on(PERMISSION_EVENTS.registerAnalyzer, (data) => {
    if (isAnalyzerRegistration(data)) analyzers.set(data.analyzer.id, data.analyzer);
  });
  pi.events.on(PERMISSION_EVENTS.registerReviewer, (data) => {
    if (isReviewerRegistration(data)) reviewers.set(data.reviewer.id, data.reviewer);
  });

  const discover = () => {
    pi.events.emit(PERMISSION_EVENTS.discover, {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
    });
  };

  pi.registerCommand("permission", {
    description: "Permissionの解析器、reviewer、ルールを表示",
    handler: async (_args, ctx) => {
      const analyzerList = byPriority(analyzers.values()).map((item) => item.id).join(", ") || "none";
      const reviewerList = byPriority(reviewers.values()).map((item) => item.id).join(", ") || "none";
      const labels = permissionLabels(language);
      const rulesStatus = rulesError
        ? language === "ja" ? `エラー (${rulesError})` : `error (${rulesError})`
        : language === "ja"
          ? `${configuredRules.length}${labels.loaded}`
          : `${configuredRules.length} ${labels.loaded}`;
      ctx.ui.notify(
        `permission\nanalyzers: ${analyzerList}\nreviewers: ${reviewerList}\n${labels.rules}: ${rulesStatus}\n${labels.rulesFile}: ${rulesPath}`,
        rulesError ? "warning" : "info",
      );
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    const request = normalizeRequest(event, ctx);
    const analyses: PermissionAnalysis[] = [];
    for (const analyzer of byPriority(analyzers.values())) {
      if (!analyzer.supports(request)) continue;
      try {
        const output = await analyzer.analyze(request, ctx);
        if (output) analyses.push({ ...output, analyzer: analyzer.id });
      } catch (error) {
        analyses.push({
          analyzer: analyzer.id,
          kind: "error",
          data: null,
          warnings: [error instanceof Error ? error.message : String(error)],
        });
      }
    }

    const policy = await evaluatePolicy(request, analyses, configuredRules);
    if (policy.decision === "allow") return undefined;
    if (policy.decision === "deny") {
      if (ctx.hasUI) {
        const labels = permissionLabels(language);
        ctx.ui.notify(
          `${labels.blocked}: ${localizedPolicyReason(policy, language)}`,
          "warning",
        );
      }
      return { block: true, reason: policy.reason };
    }

    const reviews: PermissionReview[] = [];
    if (policy.route === "model-then-human") {
      for (const reviewer of byPriority(reviewers.values())) {
        try {
          const result = await reviewer.review(request, policy, analyses, ctx);
          reviews.push({ ...result, reviewer: reviewer.id });
          if (result.decision === "allow") return undefined;
          if (result.decision === "require-human") break;
        } catch (error) {
          reviews.push({
            reviewer: reviewer.id,
            decision: "unavailable",
            reason: `Reviewer failed: ${error instanceof Error ? error.message : String(error)}`,
          });
        }
      }
    }

    if (await askHuman(request, policy, analyses, reviews, ctx, language)) return undefined;
    return {
      block: true,
      reason: ctx.hasUI
        ? permissionLabels(language).blockedByUser
        : `Permission required but no interactive UI is available: ${policy.reason}`,
    };
  });

  queueMicrotask(discover);
  pi.on("session_start", async (_event, ctx) => {
    const loaded = await loadPermissionRules(rulesPath);
    configuredRules = loaded.rules;
    language = loaded.language;
    rulesError = loaded.error;
    if (rulesError && ctx.hasUI) {
      ctx.ui.notify(
        language === "ja"
          ? `permission.jsonを無視しました: ${rulesError}`
          : `permission.json ignored: ${rulesError}`,
        "warning",
      );
    }
    discover();
  });
}
