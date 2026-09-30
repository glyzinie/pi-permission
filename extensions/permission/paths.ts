import { existsSync, realpathSync } from "node:fs";
import { lstat, readlink, realpath } from "node:fs/promises";
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
import { fileURLToPath } from "node:url";

import type { BashStaticWord } from "../permission-tree-sitter-bash/types.ts";

export interface PathIdentity {
  logical: string;
  canonical: string;
}

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

export function isInside(root: string, target: string): boolean {
  const rel = relative(resolve(root), resolve(target));
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function tempRootPaths(): string[] {
  return [...new Set(
    [tmpdir(), "/tmp", "/private/tmp", "/private/var/tmp"].map((path) => resolve(path)),
  )];
}

function resolveConfiguredPath(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "~") return resolve(homedir());
  if (trimmed.startsWith("~/")) return resolve(homedir(), trimmed.slice(2));
  return resolve(trimmed);
}

function protectedWriteRootPaths(): Record<"pi-agent" | "codex", string> {
  const piAgentDir = process.env.PI_CODING_AGENT_DIR?.trim();
  const codexHome = process.env.CODEX_HOME?.trim();
  return {
    "pi-agent": piAgentDir
      ? resolveConfiguredPath(piAgentDir)
      : resolve(homedir(), ".pi", "agent"),
    codex: codexHome
      ? resolveConfiguredPath(codexHome)
      : resolve(homedir(), ".codex"),
  };
}

function isMissingPathError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    ((error as { code?: unknown }).code === "ENOENT" ||
      (error as { code?: unknown }).code === "ENOTDIR")
  );
}

function expandToolPath(path: string, cwd: string): string {
  let value = path.startsWith("@") ? path.slice(1) : path;
  if (value.startsWith("file://")) return resolve(fileURLToPath(value));
  if (value === "~") value = homedir();
  else if (value.startsWith("~/")) value = resolve(homedir(), value.slice(2));
  return isAbsolute(value) ? resolve(value) : resolve(cwd, value);
}

async function canonicalizeAbsolute(
  absolutePath: string,
  seen: Set<string>,
): Promise<string> {
  const absolute = resolve(absolutePath);
  if (seen.has(absolute)) throw new Error(`symlink cycle while resolving ${absolute}`);
  seen.add(absolute);

  const root = parse(absolute).root;
  const components = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < components.length; index += 1) {
    const candidate = resolve(current, components[index]!);
    let stat;
    try {
      stat = await lstat(candidate);
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
      return resolve(current, ...components.slice(index));
    }
    if (!stat.isSymbolicLink()) {
      current = candidate;
      continue;
    }
    const link = await readlink(candidate);
    const linkedPath = isAbsolute(link) ? link : resolve(dirname(candidate), link);
    return canonicalizeAbsolute(
      resolve(linkedPath, ...components.slice(index + 1)),
      seen,
    );
  }

  try {
    return await realpath(current);
  } catch (error) {
    if (!isMissingPathError(error)) throw error;
    return current;
  }
}

async function identity(logical: string): Promise<PathIdentity> {
  return {
    logical,
    canonical: await canonicalizeAbsolute(logical, new Set()),
  };
}

/** Resolve a Pi tool path using Pi's @ and tilde conventions. */
export async function resolveToolPathIdentity(
  path: string,
  cwd: string,
): Promise<PathIdentity> {
  return identity(expandToolPath(path, cwd));
}

/** Resolve a statically decoded Bash word without inventing shell expansion. */
export async function resolveBashPathIdentity(
  word: BashStaticWord,
  cwd: string,
): Promise<PathIdentity> {
  if (word.value === undefined) throw new Error("Bash path is dynamic");
  const value = word.expandTilde
    ? word.value === "~"
      ? homedir()
      : resolve(homedir(), word.value.slice(2))
    : word.value;
  return identity(isAbsolute(value) ? resolve(value) : resolve(cwd, value));
}

export interface PathPolicyContext {
  readonly cwd: string;
  formsFor(path: string): readonly string[];
  tempRoots(): readonly string[];
  protectedRoots(): Readonly<Record<"pi-agent" | "codex", string>>;
  workspaceIdentity(): Promise<PathIdentity>;
  homeIdentity(): Promise<PathIdentity>;
}

/** Cache only stable roots for one policy evaluation; target identities remain fresh. */
export function createPathPolicyContext(cwd: string): PathPolicyContext {
  const forms = new Map<string, readonly string[]>();
  let tempRoots: readonly string[] | undefined;
  let protectedRoots: Readonly<Record<"pi-agent" | "codex", string>> | undefined;
  let workspacePromise: Promise<PathIdentity> | undefined;
  let homePromise: Promise<PathIdentity> | undefined;

  return {
    cwd,
    formsFor(path) {
      const logical = resolve(path);
      const cached = forms.get(logical);
      if (cached) return cached;
      const value = pathForms(logical);
      forms.set(logical, value);
      return value;
    },
    tempRoots() {
      return tempRoots ??= tempRootPaths();
    },
    protectedRoots() {
      return protectedRoots ??= protectedWriteRootPaths();
    },
    workspaceIdentity() {
      return workspacePromise ??= resolveToolPathIdentity(cwd, cwd);
    },
    homeIdentity() {
      return homePromise ??= resolveToolPathIdentity(homedir(), cwd);
    },
  };
}

function identityInside(
  value: PathIdentity,
  root: string,
  context: PathPolicyContext,
): boolean {
  return context.formsFor(root).some(
    (form) => isInside(form, value.logical) || isInside(form, value.canonical),
  );
}

function identityMatches(
  value: PathIdentity,
  path: string,
  context: PathPolicyContext,
): boolean {
  return context.formsFor(path).some(
    (form) => form === value.logical || form === value.canonical,
  );
}

function identityCovers(
  value: PathIdentity,
  path: string,
  context: PathPolicyContext,
): boolean {
  return context.formsFor(path).some(
    (form) => isInside(value.logical, form) || isInside(value.canonical, form),
  );
}

export function isTempPath(
  value: PathIdentity,
  context: PathPolicyContext,
): boolean {
  return context.tempRoots().some((root) =>
    context.formsFor(root).some((form) => isInside(form, value.canonical)),
  );
}

export function protectedRootForPath(
  value: PathIdentity,
  context: PathPolicyContext,
): { id: "pi-agent" | "codex"; path: string } | undefined {
  const roots = context.protectedRoots();
  for (const id of ["pi-agent", "codex"] as const) {
    if (identityInside(value, roots[id], context)) return { id, path: roots[id] };
  }
  return undefined;
}

export function isCredentialPath(
  value: PathIdentity,
  context: PathPolicyContext,
): boolean {
  const home = resolve(homedir());
  const roots = [resolve(home, ".ssh"), resolve(home, ".gnupg"), resolve(home, ".aws")];
  if (roots.some((root) =>
    identityInside(value, root, context) || identityCovers(value, root, context)
  )) return true;

  const protectedRoots = context.protectedRoots();
  const files = [
    resolve(home, ".netrc"),
    resolve(home, ".npmrc"),
    resolve(home, ".pypirc"),
    resolve(home, ".git-credentials"),
    resolve(home, ".docker", "config.json"),
    resolve(home, ".config", "gh", "hosts.yml"),
    resolve(home, ".config", "gcloud", "application_default_credentials.json"),
    resolve(protectedRoots["pi-agent"], "auth.json"),
    resolve(protectedRoots.codex, "auth.json"),
  ];
  return files.some((file) =>
    identityMatches(value, file, context) || identityCovers(value, file, context)
  );
}

/** Mirrors the base Bash sandbox: temp plus cwd subtree, except when cwd is HOME. */
export async function isDefaultSandboxWritable(
  value: PathIdentity,
  context: PathPolicyContext,
): Promise<boolean> {
  if (isTempPath(value, context)) return true;
  if (protectedRootForPath(value, context)) return false;
  const cwdIdentity = await context.workspaceIdentity();
  const homeIdentity = await context.homeIdentity();
  if (cwdIdentity.canonical === homeIdentity.canonical) return false;
  return isInside(cwdIdentity.canonical, value.canonical);
}
