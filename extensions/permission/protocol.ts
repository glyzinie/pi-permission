import type { ExtensionContext } from "@earendil-works/pi-coding-agent";


export const PERMISSION_PROTOCOL_VERSION = 4;
export const PERMISSION_EVENTS = {
  discover: "pi-permission:discover",
  registerAnalyzer: "pi-permission:register-analyzer",
  registerReviewer: "pi-permission:register-reviewer",
} as const;

export type PermissionReviewRoute = "model-then-human" | "human";
export type ReviewerDecision = "allow" | "require-human" | "unavailable";

export interface PermissionRequest {
  readonly toolCallId: string;
  /** Normalized tool name. MCP proxy calls become `mcp:<inner-tool>`. */
  readonly toolName: string;
  /** Original Pi tool name before normalization. */
  readonly originalToolName: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly cwd: string;
  readonly source: "pi" | "mcp";
}

export interface PermissionAnalysisResult {
  kind: string;
  data: unknown;
  warnings?: readonly string[];
}

export interface PermissionAnalysis extends PermissionAnalysisResult {
  analyzer: string;
}

export interface PermissionAnalyzer {
  id: string;
  priority?: number;
  supports(request: PermissionRequest): boolean;
  analyze(
    request: PermissionRequest,
    ctx: ExtensionContext,
  ): Promise<PermissionAnalysisResult | undefined> | PermissionAnalysisResult | undefined;
}

interface PermissionPolicyBase {
  reason: string;
  ruleId: string;
  details?: Readonly<Record<string, unknown>>;
}

export type PermissionReviewPolicy = PermissionPolicyBase & {
  decision: "review";
  route: PermissionReviewRoute;
};

export type PermissionPolicyResult =
  | (PermissionPolicyBase & { decision: "allow"; route?: never })
  | (PermissionPolicyBase & { decision: "deny"; route?: never })
  | PermissionReviewPolicy;

export interface PermissionReviewResult {
  decision: ReviewerDecision;
  reason: string;
  details?: Record<string, unknown>;
}

export interface PermissionReview extends PermissionReviewResult {
  reviewer: string;
}

export interface PermissionReviewer {
  id: string;
  priority?: number;
  review(
    request: PermissionRequest,
    policy: PermissionReviewPolicy,
    analyses: readonly PermissionAnalysis[],
    ctx: ExtensionContext,
  ): Promise<PermissionReviewResult>;
}

export interface RegisterAnalyzerEvent {
  protocolVersion: typeof PERMISSION_PROTOCOL_VERSION;
  analyzer: PermissionAnalyzer;
}

export interface RegisterReviewerEvent {
  protocolVersion: typeof PERMISSION_PROTOCOL_VERSION;
  reviewer: PermissionReviewer;
}
