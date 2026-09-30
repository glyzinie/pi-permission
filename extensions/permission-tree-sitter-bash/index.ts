import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  PERMISSION_EVENTS,
  PERMISSION_PROTOCOL_VERSION,
  type PermissionAnalyzer,
  type RegisterAnalyzerEvent,
} from "../permission/protocol.ts";
import {
  BASH_ANALYSIS_KIND,
  TREE_SITTER_BASH_PLUGIN_ID,
  type BashTreeSitterAnalysis,
} from "./types.ts";

type AnalyzerModule = typeof import("./bash-cst.ts");

let analyzerModulePromise: Promise<AnalyzerModule> | undefined;

function loadAnalyzerModule(): Promise<AnalyzerModule> {
  analyzerModulePromise ??= import("./bash-cst.ts");
  return analyzerModulePromise;
}

export async function analyzeBashSource(
  source: string,
): Promise<BashTreeSitterAnalysis> {
  return (await loadAnalyzerModule()).analyzeBashSource(source);
}

function invalidBashInput(warning: string): BashTreeSitterAnalysis {
  return {
    raw: "",
    complete: false,
    dynamic: true,
    opaque: true,
    background: false,
    controlOperators: [],
    commands: [],
    writeTargets: [],
    writeTargetsComplete: false,
    warnings: [warning],
  };
}

const analyzer: PermissionAnalyzer = {
  id: TREE_SITTER_BASH_PLUGIN_ID,
  priority: 100,
  supports: (request) => request.toolName === "bash",
  async analyze(request) {
    const command = request.input.command;
    const data = typeof command === "string"
      ? await analyzeBashSource(command)
      : invalidBashInput("bash input.command is not a string");
    return {
      kind: BASH_ANALYSIS_KIND,
      data,
      warnings: data.warnings,
    };
  },
};

export default function permissionTreeSitterBash(pi: ExtensionAPI): void {
  const register = () => {
    const event: RegisterAnalyzerEvent = {
      protocolVersion: PERMISSION_PROTOCOL_VERSION,
      analyzer,
    };
    pi.events.emit(PERMISSION_EVENTS.registerAnalyzer, event);
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

export type { BashTreeSitterAnalysis } from "./types.ts";
