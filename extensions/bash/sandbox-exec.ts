import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";

import {
  getShellConfig,
  type BashOperations,
} from "@earendil-works/pi-coding-agent";

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const POST_EXIT_IDLE_MS = 100;
const POST_EXIT_MAX_MS = 1_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const MAX_TIMEOUT_SECONDS = MAX_TIMEOUT_MS / 1000;
const UNSAFE_ENV_KEY = /^(?:BASH_ENV|ENV|CDPATH|GLOBIGNORE|ZDOTDIR|SHELLOPTS|BASHOPTS|LD_PRELOAD|LD_LIBRARY_PATH|BASH_FUNC_.*|DYLD_.*)$/;

export interface SandboxPaths {
  executionRoot: string;
  writableRoot?: string;
  protectedRoots: string[];
  protectedAncestors: string[];
}

export interface SandboxRuntime {
  readonly operations: BashOperations;
  close(): void;
}

// Keep enforcement path handling independent from Permission classification.
function canonicalOrResolve(path: string): string {
  const resolved = resolve(path);
  const missing: string[] = [];
  let current = resolved;
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return resolved;
    missing.unshift(basename(current));
    current = parent;
  }
  try {
    return resolve(realpathSync(current), ...missing);
  } catch {
    return resolved;
  }
}

function pathForms(path: string): string[] {
  const logical = resolve(path);
  return [...new Set([logical, canonicalOrResolve(logical)])];
}

function isInside(root: string, target: string): boolean {
  const rel = relative(resolve(root), resolve(target));
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function tempRootPaths(): string[] {
  return [...new Set(
    [tmpdir(), "/tmp", "/private/tmp", "/private/var/tmp"].map((path) => resolve(path)),
  )];
}

function configuredRoot(value: string | undefined, fallback: string): string {
  const configured = value?.trim();
  if (!configured) return resolve(homedir(), fallback);
  if (configured === "~") return resolve(homedir());
  return configured.startsWith("~/")
    ? resolve(homedir(), configured.slice(2))
    : resolve(configured);
}

function protectedWriteRoots(): string[] {
  return [
    configuredRoot(process.env.PI_CODING_AGENT_DIR, ".pi/agent"),
    configuredRoot(process.env.CODEX_HOME, ".codex"),
  ];
}

function uniquePaths(paths: readonly string[]): string[] {
  return [...new Set(paths.map((path) => resolve(path)))];
}

function ancestors(path: string): string[] {
  const result: string[] = [];
  const root = parse(resolve(path)).root;
  let current = dirname(resolve(path));
  while (current !== root) {
    result.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return result;
}

export function resolveSandboxPaths(launchCwd: string): SandboxPaths {
  const home = canonicalOrResolve(homedir());
  const cwd = canonicalOrResolve(launchCwd);
  const protectedRoots = uniquePaths(protectedWriteRoots().flatMap(pathForms));

  return {
    executionRoot: cwd,
    writableRoot: cwd === home ? undefined : cwd,
    protectedRoots,
    protectedAncestors: uniquePaths(
      protectedRoots.flatMap((root) => ancestors(root)),
    ),
  };
}

function literal(path: string): string {
  return `(literal ${JSON.stringify(path)})`;
}

function subpath(path: string): string {
  return `(subpath ${JSON.stringify(path)})`;
}

function renderRule(effect: "allow" | "deny", operations: string, filters: readonly string[]): string {
  if (filters.length === 0) return "";
  return `(${effect} ${operations}\n${filters.map((filter) => `  ${filter}`).join("\n")})`;
}

export function sandboxProfile(paths: SandboxPaths): string {
  const baseRoots = [
    ...(paths.writableRoot ? [paths.writableRoot] : []),
    ...tempRootPaths(),
  ].flatMap(pathForms);
  const baseWriteFilters = uniquePaths(baseRoots).map(subpath);
  const protectedFilters = [
    ...paths.protectedRoots.map(literal),
    ...paths.protectedRoots.map(subpath),
  ];
  const ancestorFilters = paths.protectedAncestors.map(literal);

  const writeRules = [
    renderRule("allow", "file-write*", baseWriteFilters),
    renderRule("deny", "file-write*", protectedFilters),
    renderRule("deny", "file-write-create file-write-unlink", ancestorFilters),
  ].filter(Boolean).join("\n");

  return `(version 1)
(deny default)
(import "bsd.sb")

; The selected shell still needs to fork ordinary external utilities.
(allow process-fork)
(allow process-exec)
(allow signal (target self))
(deny process-info*)
(allow process-info* (target self))

; This profile is a write boundary. Reads and network access are unrestricted.
(allow file-read*)
(allow network*)

${writeRules}
`;
}

export function resolveSandboxTimeoutMs(timeout: number | undefined): number | undefined {
  if (timeout === undefined) return undefined;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error("Invalid timeout: must be a finite number of seconds");
  }
  const timeoutMs = timeout * 1000;
  if (timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`Invalid timeout: maximum is ${MAX_TIMEOUT_SECONDS} seconds`);
  }
  return timeoutMs;
}

function sanitizedEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result = { ...env };
  for (const key of Object.keys(result)) {
    if (UNSAFE_ENV_KEY.test(key)) delete result[key];
  }
  return result;
}

export function sandboxShellArgsWithoutStartupFiles(
  shellPath: string,
  args: readonly string[],
): string[] {
  const shell = basename(canonicalOrResolve(shellPath));
  if (shell === "bash") return ["--noprofile", "--norc", ...args];
  if (shell === "zsh") return ["-f", ...args];
  if (shell === "fish") return ["--no-config", ...args];
  return [...args];
}

function killProcessGroup(pid: number): void {
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Process already exited.
    }
  }
}

export function createSandboxRuntime(
  launchCwd: string,
  shellPath?: string,
): SandboxRuntime {
  if (process.platform !== "darwin") {
    throw new Error("pi-sandbox-exec supports macOS only");
  }
  if (!existsSync(SANDBOX_EXEC)) {
    throw new Error(`${SANDBOX_EXEC} is unavailable`);
  }

  const shell = getShellConfig(shellPath);
  if (!isAbsolute(shell.shell) || !existsSync(shell.shell)) {
    throw new Error(`sandbox shell must be an existing absolute path: ${shell.shell}`);
  }

  const paths = resolveSandboxPaths(launchCwd);
  const activeProcessGroups = new Set<number>();
  const profile = sandboxProfile(paths);
  const shellArgs = sandboxShellArgsWithoutStartupFiles(shell.shell, shell.args);

  return {
    operations: {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        const timeoutMs = resolveSandboxTimeoutMs(timeout);
        const current = canonicalOrResolve(cwd);
        if (!isInside(paths.executionRoot, current)) {
          throw new Error(`bash cwd is outside sandbox execution root: ${current}`);
        }

        return new Promise((resolvePromise, reject) => {
          if (signal?.aborted) {
            reject(new Error("aborted"));
            return;
          }

          const child = spawn(
            SANDBOX_EXEC,
            ["-p", profile, shell.shell, ...shellArgs, command],
            {
              cwd: current,
              env: sanitizedEnvironment(env ?? process.env),
              detached: true,
              stdio: ["ignore", "pipe", "pipe"],
            },
          );
          if (child.pid) activeProcessGroups.add(child.pid);

          let settled = false;
          let timedOut = false;
          let exited = false;
          let exitCode: number | null = null;
          let openStreams = Number(child.stdout !== null) + Number(child.stderr !== null);
          let timeoutTimer: NodeJS.Timeout | undefined;
          let postExitTimer: NodeJS.Timeout | undefined;
          let postExitMaxTimer: NodeJS.Timeout | undefined;

          const kill = () => {
            if (child.pid) killProcessGroup(child.pid);
          };
          const cleanup = () => {
            for (const timer of [timeoutTimer, postExitTimer, postExitMaxTimer]) {
              if (timer) clearTimeout(timer);
            }
            signal?.removeEventListener("abort", kill);
            child.removeListener("error", onError);
            child.removeListener("exit", onExit);
            child.removeListener("close", onClose);
            child.stdout?.removeListener("data", onOutput);
            child.stderr?.removeListener("data", onOutput);
            child.stdout?.removeListener("end", onStreamEnd);
            child.stderr?.removeListener("end", onStreamEnd);
            if (child.pid) activeProcessGroups.delete(child.pid);
          };
          const finish = (fn: () => void) => {
            if (settled) return;
            settled = true;
            cleanup();
            child.stdout?.destroy();
            child.stderr?.destroy();
            fn();
          };
          const complete = (code: number | null) => {
            finish(() => {
              if (signal?.aborted) reject(new Error("aborted"));
              else if (timedOut) reject(new Error(`timeout:${timeout}`));
              else resolvePromise({ exitCode: code });
            });
          };
          const armPostExitIdle = () => {
            if (postExitTimer) clearTimeout(postExitTimer);
            postExitTimer = setTimeout(() => complete(exitCode), POST_EXIT_IDLE_MS);
          };
          const maybeCompleteAfterExit = () => {
            if (exited && openStreams === 0) complete(exitCode);
          };
          const onOutput = (data: Buffer) => {
            onData(data);
            if (exited && !timedOut && !signal?.aborted) armPostExitIdle();
          };
          const onStreamEnd = () => {
            openStreams -= 1;
            maybeCompleteAfterExit();
          };
          const onError = (error: Error) => finish(() => reject(error));
          const onExit = (code: number | null) => {
            exited = true;
            exitCode = code;
            // A foreground shell may leave descendants holding inherited pipes.
            kill();
            maybeCompleteAfterExit();
            if (!settled) {
              armPostExitIdle();
              postExitMaxTimer = setTimeout(() => complete(exitCode), POST_EXIT_MAX_MS);
            }
          };
          const onClose = (code: number | null) => complete(code ?? exitCode);

          child.stdout?.on("data", onOutput);
          child.stderr?.on("data", onOutput);
          child.stdout?.once("end", onStreamEnd);
          child.stderr?.once("end", onStreamEnd);
          child.once("error", onError);
          child.once("exit", onExit);
          child.once("close", onClose);

          if (signal?.aborted) kill();
          else signal?.addEventListener("abort", kill, { once: true });
          if (timeoutMs !== undefined) {
            timeoutTimer = setTimeout(() => {
              timedOut = true;
              kill();
            }, timeoutMs);
          }
        });
      },
    },
    close() {
      for (const pid of activeProcessGroups) killProcessGroup(pid);
      activeProcessGroups.clear();
    },
  };
}
