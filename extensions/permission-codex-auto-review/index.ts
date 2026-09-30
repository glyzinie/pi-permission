import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  PERMISSION_EVENTS,
  PERMISSION_PROTOCOL_VERSION,
  type RegisterReviewerEvent,
} from "../permission/protocol.ts";
import { codexAutoReviewer } from "./reviewer.ts";

export default function permissionCodexAutoReview(pi: ExtensionAPI): void {
  const register = () => {
    const event: RegisterReviewerEvent = {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
      reviewer: codexAutoReviewer,
    };
    pi.events.emit(PERMISSION_EVENTS.registerReviewer, event);
  };

  pi.events.on(PERMISSION_EVENTS.discover, (data) => {
    if (
      typeof data === "object" &&
      data !== null &&
      "protocolVersion" in data &&
      data.protocolVersion === PERMISSION_PROTOCOL_VERSION
    ) {
      register();
    }
  });

  register();
}

export { parseReviewResponse } from "./contract.ts";
export { buildReviewEvidence } from "./evidence.ts";
export { resolveCodexReviewModel } from "./model.ts";
