import type { Model } from "@earendil-works/pi-ai";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

export const CODEX_PROVIDER_ID = "openai-codex" as const;
export const CODEX_AUTO_REVIEW_MODEL_ID = "codex-auto-review" as const;

type CodexModel = Model<"openai-codex-responses">;

function isCodexModel(model: Model<any> | undefined): model is CodexModel {
  return (
    model?.provider === CODEX_PROVIDER_ID &&
    model.api === "openai-codex-responses"
  );
}

export function resolveCodexReviewModel(
  ctx: ExtensionContext,
): CodexModel | undefined {
  const registered = ctx.modelRegistry.find(
    CODEX_PROVIDER_ID,
    CODEX_AUTO_REVIEW_MODEL_ID,
  );
  if (isCodexModel(registered)) return registered;

  const template = ctx.modelRegistry.getAll().find(isCodexModel);
  if (!template) return undefined;
  return {
    ...template,
    id: CODEX_AUTO_REVIEW_MODEL_ID,
    name: "Codex Auto Review",
    reasoning: true,
    input: ["text"],
  };
}
