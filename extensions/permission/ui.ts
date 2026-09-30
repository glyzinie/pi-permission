import type {
  PermissionPolicyResult,
  PermissionReview,
} from "./protocol.ts";

export type PermissionLanguage = "en" | "ja";

const JA_REASONS: Readonly<Record<string, string>> = {
  "builtin-read": "読み取り専用の組み込みツールです。",
  "credential-read": "認証情報へのアクセスには明示的な許可が必要です。",
  "read-path-unresolved": "読み取り対象のパスを安全に解決できませんでした。",
  "write-path-missing": "書き込み対象のパスが指定されていません。",
  "write-path-unresolved": "書き込み対象のパスを安全に解決できませんでした。",
  "credential-write": "認証情報の変更には明示的な許可が必要です。",
  "protected-config-write": "PiまたはCodexの設定変更には確認が必要です。",
  "temporary-write": "一時ディレクトリへの書き込みです。",
  "workspace-write": "workspace内への書き込みです。",
  "outside-workspace-write": "workspace外への書き込みには確認が必要です。",
  "bash-command-missing": "Bashコマンドが指定されていません。",
  "bash-analyzer-unavailable": "Bashの解析結果を利用できないため、人間の確認が必要です。",
  "dangerous-shell-operation": "危険なシェル操作として拒否されました。",
  "bash-deletion-disallowed": "Bashによる削除は無効です。復旧可能なtrashを使用してください。",
  "credential-shell-access": "Bashコマンドが認証情報を参照するため、人間の確認が必要です。",
  "bash-write-target-unresolved": "Bashの書き込み先を安全に解決できませんでした。",
  "bash-credential-write-disallowed": "Bashから認証情報を変更できません。writeまたはeditを使用してください。",
  "bash-protected-write-disallowed": "BashからPiまたはCodexの設定を変更できません。writeまたはeditを使用してください。",
  "bash-outside-sandbox-write-disallowed": "Bashからworkspaceまたは一時ディレクトリの外へ書き込めません。writeまたはeditを使用してください。",
  "privileged-shell-command": "特権コマンドには明示的な許可が必要です。",
  "safe-static-shell": "静的に解析できる低リスクなコマンドです。",
  "complex-shell-command": "動的または完全に解析できないシェル構文のため、確認が必要です。",
  "unrecognized-shell-command": "決定的な低リスクルールに一致しないコマンドです。",
  "credential-external-tool": "外部ツールが認証情報を参照するため、人間の確認が必要です。",
  "external-tool-path-unresolved": "外部ツールのパスを安全に解決できませんでした。",
  "configured-tool-rule": "permission.jsonのルールに従って確認します。",
  "known-self-enforcing-tool": "ツール自身がworkspace境界を検証します。",
  "custom-tool": "customまたは外部ツールのため、確認が必要です。",
};

export function localizedPolicyReason(
  policy: PermissionPolicyResult,
  language: PermissionLanguage,
): string {
  if (language !== "ja") return policy.reason;
  const reason = JA_REASONS[policy.ruleId] ?? policy.reason;
  const target = policy.details?.target;
  return typeof target === "string" ? `${reason}\n対象: ${target}` : reason;
}

export function localizedReviewReason(
  review: PermissionReview,
  language: PermissionLanguage,
): string {
  if (language !== "ja") return review.reason;
  if (review.decision === "unavailable") {
    return `自動レビューを利用できませんでした。\n詳細: ${review.reason}`;
  }
  if (review.decision === "require-human") {
    return `自動承認されませんでした。\n詳細: ${review.reason}`;
  }
  return `低リスクとして自動承認されました。\n詳細: ${review.reason}`;
}

export function permissionLabels(language: PermissionLanguage) {
  return language === "ja"
    ? {
        title: "権限の確認",
        reason: "理由",
        input: "入力",
        analyzers: "解析",
        reviewer: "Codexレビュー",
        allowOnce: "今回のみ許可",
        block: "拒否",
        blocked: "Permissionにより拒否しました",
        blockedByUser: "ユーザーが拒否しました",
        rules: "ルール",
        rulesFile: "ルールファイル",
        loaded: "件を読み込み済み",
      }
    : {
        title: "Permission required",
        reason: "Reason",
        input: "Input",
        analyzers: "Analyzers",
        reviewer: "Reviewer",
        allowOnce: "Allow once",
        block: "Block",
        blocked: "Blocked by permission",
        blockedByUser: "Blocked by user",
        rules: "rules",
        rulesFile: "rules file",
        loaded: "loaded",
      };
}
