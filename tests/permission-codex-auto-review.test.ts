import { describe, expect, test } from "bun:test";

import {
  buildReviewEvidence,
  parseReviewResponse,
  resolveCodexReviewModel,
} from "../extensions/permission-codex-auto-review/index.ts";
import { buildReviewPrompt } from "../extensions/permission-codex-auto-review/contract.ts";
import { codexAutoReviewer } from "../extensions/permission-codex-auto-review/reviewer.ts";
import type {
  PermissionAnalysis,
  PermissionRequest,
  PermissionReviewPolicy,
} from "../extensions/permission/protocol.ts";

const request: PermissionRequest = {
  toolCallId: "call-1",
  toolName: "write",
  originalToolName: "write",
  input: { path: "/tmp/settings.json", content: "{\"theme\":\"dark\"}" },
  cwd: "/tmp",
  source: "pi",
};
const policy = {
  decision: "review",
  route: "model-then-human",
  ruleId: "protected-config-write",
  reason: "configuration write requires review",
} satisfies PermissionReviewPolicy;

describe("Codex auto-review contract", () => {
  test("accepts only strict low-risk allow shapes", () => {
    expect(parseReviewResponse('{"outcome":"allow"}')).toMatchObject({
      outcome: "allow",
      riskLevel: "low",
    });
    expect(parseReviewResponse('{"outcome":"allow","risk_level":"low","rationale":"bounded"}')).toEqual({
      outcome: "allow",
      riskLevel: "low",
      rationale: "bounded",
    });
  });

  test("rejects prose, missing fields, extra fields, and non-low allows", () => {
    expect(() => parseReviewResponse('```json\n{"outcome":"allow"}\n```')).toThrow();
    expect(() => parseReviewResponse('{"outcome":"allow","risk_level":"typo","rationale":"x"}')).toThrow();
    expect(() => parseReviewResponse('{"outcome":"allow","risk_level":"medium","rationale":"x"}')).toThrow();
    expect(() => parseReviewResponse('{"outcome":"deny","risk_level":"high"}')).toThrow();
    expect(() => parseReviewResponse('{"outcome":"allow","extra":true}')).toThrow();
  });
});

describe("Codex auto-review model resolution", () => {
  test("uses only the Codex Responses API and synthesizes the review alias", () => {
    const template = {
      id: "gpt-codex",
      name: "Codex",
      provider: "openai-codex",
      api: "openai-codex-responses",
      baseUrl: "https://example.test",
      reasoning: true,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 100_000,
      maxTokens: 4_000,
    };
    const ctx = {
      modelRegistry: {
        find: () => undefined,
        getAll: () => [template],
      },
    } as any;
    expect(resolveCodexReviewModel(ctx)).toMatchObject({
      id: "codex-auto-review",
      provider: "openai-codex",
      api: "openai-codex-responses",
    });
  });
});

describe("Codex auto-review request", () => {
  test("uses a reasoning summary value supported by the Codex API", async () => {
    let completionOptions: Record<string, unknown> | undefined;
    const model = {
      id: "codex-auto-review",
      name: "Codex Auto Review",
      provider: "openai-codex",
      api: "openai-codex-responses",
      reasoning: true,
      input: ["text"],
    };
    const ctx = {
      modelRegistry: {
        find: () => model,
        getAll: () => [model],
        complete: async (_model: unknown, _context: unknown, options: Record<string, unknown>) => {
          completionOptions = options;
          return {
            role: "assistant",
            content: [{ type: "text", text: '{"outcome":"allow"}' }],
            stopReason: "stop",
          };
        },
      },
    } as any;

    const result = await codexAutoReviewer.review(request, policy, [], ctx);

    expect(result.decision).toBe("allow");
    expect(completionOptions?.reasoningSummary).toBe("concise");
  });
});

describe("Codex auto-review evidence", () => {
  test("projects bounded benign evidence", () => {
    const evidence = buildReviewEvidence(request, policy, []);
    expect(evidence.safeForAutoReview).toBe(true);
    expect(evidence.serialized).toBe(JSON.stringify(evidence.value));
  });

  test("reuses compact evidence JSON in the review prompt", () => {
    const evidence = buildReviewEvidence(request, policy, []);
    expect(evidence.serialized).toBeDefined();

    const prompt = buildReviewPrompt(evidence.serialized!);
    expect(prompt).toContain(`>>> EVIDENCE START\n${evidence.serialized}\n>>> EVIDENCE END`);
    expect(prompt).not.toContain(JSON.stringify(evidence.value, null, 2));
  });

  test("fails closed when the cumulative projection budget is exhausted", async () => {
    const items = Array.from({ length: 40 }, (_, itemIndex) =>
      Object.fromEntries(
        Array.from({ length: 80 }, (_, keyIndex) => [
          `key-${keyIndex}`,
          `value-${itemIndex}-${keyIndex}`,
        ]),
      ),
    );
    const broadRequest = { ...request, input: { items } };
    const evidence = buildReviewEvidence(broadRequest, policy, []);

    expect(evidence.safeForAutoReview).toBe(false);
    expect(evidence.serialized).toBeUndefined();
    expect(JSON.stringify(evidence.value)).toContain("[omitted]");

    const result = await codexAutoReviewer.review(
      broadRequest,
      policy,
      [],
      {} as any,
    );
    expect(result.decision).toBe("require-human");
  });

  test("keeps benign shared Bash analysis values eligible for auto-review", () => {
    const warnings: string[] = [];
    const path = {
      raw: "output.txt",
      value: "output.txt",
      quoted: false,
      expandTilde: false,
    };
    const analyses: PermissionAnalysis[] = [{
      analyzer: "tree-sitter-bash",
      kind: "bash/tree-sitter",
      data: {
        raw: "printf ok > output.txt",
        complete: true,
        dynamic: false,
        opaque: false,
        background: false,
        controlOperators: [],
        commands: [{
          words: [],
          resolvedArgv: ["printf", "ok"],
          assignments: [],
          redirects: [{ operator: ">", target: path, write: true }],
          effectsComplete: true,
        }],
        writeTargets: [{ path, mode: "file", operation: "redirect >" }],
        writeTargetsComplete: true,
        warnings,
      },
      warnings,
    }];
    const evidence = buildReviewEvidence(
      {
        ...request,
        toolName: "bash",
        originalToolName: "bash",
        input: { command: "printf ok > output.txt" },
      },
      {
        ...policy,
        ruleId: "complex-shell-command",
        reason: "shell command requires review",
      },
      analyses,
    );
    expect(evidence.safeForAutoReview).toBe(true);
  });

  test("does not send secret-bearing content or analyzer warnings", () => {
    for (const [content, analyses] of [
      ["-----BEGIN PRIVATE KEY-----\nsecret", []],
      ['{"api_key":"sk-abcdefghijklmnop"}', []],
      ["safe", [{ analyzer: "x", kind: "error", data: null, warnings: ["Bearer abc.def.ghi"] }]],
    ] as const) {
      const evidence = buildReviewEvidence(
        {
          ...request,
          input: { path: "/tmp/auth.json", content },
        },
        policy,
        analyses,
      );
      expect(evidence.safeForAutoReview).toBe(false);
      expect(evidence.serialized).toBeUndefined();
      const serialized = JSON.stringify(evidence.value);
      expect(serialized).not.toContain("PRIVATE KEY");
      expect(serialized).not.toContain("sk-abcdefghijklmnop");
      expect(serialized).not.toContain("abc.def.ghi");
    }
  });
});
