import {
  SettingsManager,
  createBashToolDefinition,
  createLocalBashOperations,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";

import {
  createSandboxRuntime,
  type SandboxRuntime,
} from "./sandbox-exec.ts";

interface ShellSettings {
  shellPath?: string;
  commandPrefix?: string;
}

interface BashExtensionOptions {
  platform?: NodeJS.Platform;
  createSandbox?: typeof createSandboxRuntime;
}

function loadShellSettings(ctx: ExtensionContext): ShellSettings {
  const settings = SettingsManager.create(ctx.cwd, undefined, {
    projectTrusted: ctx.isProjectTrusted(),
  });
  const errors = settings.drainErrors();
  if (errors.length > 0 && ctx.hasUI) {
    ctx.ui.notify(
      `pi-bash could not read all shell settings; using resolved defaults:\n${errors
        .map((item) => `${item.scope}: ${item.error.message}`)
        .join("\n")}`,
      "warning",
    );
  }
  return {
    shellPath: settings.getShellPath(),
    commandPrefix: settings.getShellCommandPrefix(),
  };
}

export default function bashExtension(
  pi: ExtensionAPI,
  options: BashExtensionOptions = {},
): void {
  const platform = options.platform ?? process.platform;
  const createSandbox = options.createSandbox ?? createSandboxRuntime;
  const base = createBashToolDefinition(process.cwd());
  let activeTool: typeof base | undefined;
  let sandbox: SandboxRuntime | undefined;

  pi.registerTool({
    ...base,
    promptSnippet: "Execute shell commands only when no dedicated tool applies",
    promptGuidelines: [],
    async execute(id, params, signal, onUpdate, ctx) {
      if (!activeTool) {
        throw new Error(
          platform === "darwin"
            ? "macOS filesystem sandbox is not initialized for bash"
            : "bash is not initialized",
        );
      }
      return activeTool.execute(id, params, signal, onUpdate, ctx);
    },
  });

  pi.on("session_start", (_event, ctx) => {
    sandbox?.close();
    sandbox = undefined;
    activeTool = undefined;

    const settings = loadShellSettings(ctx);
    const operations = platform === "darwin"
      ? (sandbox = createSandbox(ctx.cwd, settings.shellPath)).operations
      : createLocalBashOperations({ shellPath: settings.shellPath });
    activeTool = createBashToolDefinition(ctx.cwd, {
      operations,
      commandPrefix: settings.commandPrefix,
    });
  });

  pi.on("session_shutdown", () => {
    activeTool = undefined;
    sandbox?.close();
    sandbox = undefined;
  });
}
