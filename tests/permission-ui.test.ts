import { describe, expect, test } from "bun:test";

import {
  localizedPolicyReason,
  localizedReviewReason,
  permissionLabels,
} from "../extensions/permission/ui.ts";
import type {
  PermissionPolicyResult,
  PermissionReview,
} from "../extensions/permission/protocol.ts";

const policy = {
  decision: "review",
  route: "human",
  ruleId: "credential-read",
  reason: "credential path access requires explicit approval",
  details: { target: "/Users/example/.ssh/id_ed25519" },
} satisfies PermissionPolicyResult;

describe("Permission Japanese UI", () => {
  test("localizes known policy reasons while preserving targets", () => {
    const text = localizedPolicyReason(policy, "ja");
    expect(text).toContain("認証情報へのアクセス");
    expect(text).toContain("/Users/example/.ssh/id_ed25519");
    expect(localizedPolicyReason(policy, "en")).toBe(policy.reason);
  });

  test("localizes buttons and section labels", () => {
    const labels = permissionLabels("ja");
    expect(labels.title).toBe("権限の確認");
    expect(labels.allowOnce).toBe("今回のみ許可");
    expect(labels.block).toBe("拒否");
    expect(labels.analyzers).toBe("解析");
  });

  test("localizes reviewer status without altering technical details", () => {
    const review = {
      reviewer: "codex-auto-review",
      decision: "require-human",
      reason: "risk: medium",
    } satisfies PermissionReview;
    const text = localizedReviewReason(review, "ja");
    expect(text).toContain("自動承認されませんでした");
    expect(text).toContain("risk: medium");
  });

  test("falls back to the original reason for unknown rule IDs", () => {
    const unknown = {
      ...policy,
      ruleId: "future-rule",
      reason: "future reason",
    } satisfies PermissionPolicyResult;
    expect(localizedPolicyReason(unknown, "ja")).toContain("future reason");
  });
});
