import type { AssistantMessage } from "@earendil-works/pi-ai";

import type {
  PermissionReviewer,
  PermissionReviewResult,
} from "../permission/protocol.ts";
import {
  buildReviewPrompt,
  parseReviewResponse,
  REVIEW_SYSTEM_PROMPT,
} from "./contract.ts";
import { buildReviewEvidence } from "./evidence.ts";
import { resolveCodexReviewModel } from "./model.ts";

const TIMEOUT_MS = 90_000;

function responseText(message: AssistantMessage): string {
  return message.content
    .filter((block): block is Extract<(typeof message.content)[number], { type: "text" }> =>
      block.type === "text",
    )
    .map((block) => block.text)
    .join("")
    .trim();
}

export const codexAutoReviewer: PermissionReviewer = {
  id: "codex-auto-review",
  priority: 100,
  async review(request, policy, analyses, ctx): Promise<PermissionReviewResult> {
    const evidence = buildReviewEvidence(request, policy, analyses);
    if (!evidence.safeForAutoReview) {
      return {
        decision: "require-human",
        reason: "Review evidence contained a secret, cycle, unsupported value, or size truncation and was not sent to Codex.",
      };
    }

    const model = resolveCodexReviewModel(ctx);
    if (!model) {
      return {
        decision: "unavailable",
        reason: "A compatible openai-codex review model is unavailable.",
      };
    }

    const timeoutSignal = AbortSignal.timeout(TIMEOUT_MS);
    const signal = ctx.signal
      ? AbortSignal.any([ctx.signal, timeoutSignal])
      : timeoutSignal;

    let message: AssistantMessage;
    try {
      message = await ctx.modelRegistry.complete(
        model,
        {
          systemPrompt: REVIEW_SYSTEM_PROMPT,
          messages: [{
            role: "user",
            content: buildReviewPrompt(evidence.serialized),
            timestamp: Date.now(),
          }],
        },
        {
          signal,
          timeoutMs: TIMEOUT_MS,
          maxRetries: 0,
          reasoningEffort: "low",
          reasoningSummary: "concise",
          textVerbosity: "low",
          toolChoice: "none",
        },
      );
    } catch (error) {
      return {
        decision: "unavailable",
        reason: `Codex review failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    if (message.stopReason !== "stop") {
      return {
        decision: "unavailable",
        reason: message.errorMessage ?? `Codex review stopped with ${message.stopReason}.`,
      };
    }

    try {
      const payload = parseReviewResponse(responseText(message));
      if (payload.outcome === "allow" && payload.riskLevel === "low") {
        return {
          decision: "allow",
          reason: `Low-risk auto-approval: ${payload.rationale}`,
          details: { riskLevel: payload.riskLevel, usage: message.usage },
        };
      }
      return {
        decision: "require-human",
        reason: `Codex did not auto-approve (risk: ${payload.riskLevel}): ${payload.rationale}`,
        details: { riskLevel: payload.riskLevel, usage: message.usage },
      };
    } catch (error) {
      return {
        decision: "unavailable",
        reason: `Codex returned an invalid review response: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  },
};
