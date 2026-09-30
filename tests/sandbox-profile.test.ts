import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  resolveSandboxPaths,
  resolveSandboxTimeoutMs,
  sandboxProfile,
  sandboxShellArgsWithoutStartupFiles,
  type SandboxPaths,
} from "../extensions/bash/sandbox-exec.ts";

const originalPiAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalCodexHome = process.env.CODEX_HOME;
afterEach(() => {
  if (originalPiAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = originalPiAgentDir;
  if (originalCodexHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = originalCodexHome;
});

const paths: SandboxPaths = {
  executionRoot: "/work/project",
  writableRoot: "/work/project",
  protectedRoots: ["/home/user/.pi/agent", "/home/user/.codex"],
  protectedAncestors: ["/home/user/.pi", "/home/user"],
};

describe("sandboxProfile", () => {
  test("keeps protected roots denied in the static profile", () => {
    const profile = sandboxProfile(paths);
    expect(profile).toContain('(deny file-write*\n  (literal "/home/user/.pi/agent")');
    expect(profile).toContain('(subpath "/home/user/.codex")');
    expect(profile).not.toContain("file-write* file-write-create file-write-unlink");
  });

  test("prevents protected ancestors from being renamed", () => {
    const profile = sandboxProfile(paths);
    const ancestorDenyIndex = profile.indexOf(
      '(deny file-write-create file-write-unlink',
    );
    expect(ancestorDenyIndex).toBeGreaterThanOrEqual(0);
    expect(profile.slice(ancestorDenyIndex)).toContain('(literal "/home/user/.pi")');
  });

  test("does not add a HOME direct-child write exception", () => {
    const homeLaunch: SandboxPaths = {
      ...paths,
      writableRoot: undefined,
    };
    const profile = sandboxProfile(homeLaunch);
    expect(profile).not.toContain("(regex");
    expect(profile).not.toContain('(subpath "/home/user")');
  });

  test("documents unrestricted reads and network", () => {
    const profile = sandboxProfile(paths);
    expect(profile).toContain("(allow file-read*)");
    expect(profile).toContain("(allow network*)");
  });
});

describe("resolveSandboxPaths", () => {
  test("preserves logical and canonical protected-root forms", () => {
    const base = "/tmp/pi-sandbox-path-forms-test";
    const workspace = `${base}/workspace`;
    const piActual = `${base}/actual/pi-agent`;
    const codexActual = `${base}/actual/codex`;
    const piLogical = `${base}/links/pi-agent`;
    const codexLogical = `${base}/links/codex`;
    rmSync(base, { recursive: true, force: true });
    mkdirSync(workspace, { recursive: true });
    mkdirSync(piActual, { recursive: true });
    mkdirSync(codexActual, { recursive: true });
    mkdirSync(dirname(piLogical), { recursive: true });
    symlinkSync(piActual, piLogical);
    symlinkSync(codexActual, codexLogical);
    process.env.PI_CODING_AGENT_DIR = piLogical;
    process.env.CODEX_HOME = codexLogical;

    const resolved = resolveSandboxPaths(workspace);
    expect(resolved.protectedRoots).toContain(resolve(piLogical));
    expect(resolved.protectedRoots).toContain(realpathSync(piLogical));
    expect(resolved.protectedRoots).toContain(resolve(codexLogical));
    expect(resolved.protectedRoots).toContain(realpathSync(codexLogical));
    expect(resolved.protectedAncestors).toContain(dirname(resolve(piLogical)));
    expect(resolved.protectedAncestors).toContain(dirname(realpathSync(piLogical)));

    rmSync(base, { recursive: true, force: true });
  });

  test("canonicalizes a missing protected root through an existing symlink parent", () => {
    const base = "/tmp/pi-sandbox-missing-root-test";
    const workspace = `${base}/workspace`;
    const actualParent = `${base}/actual`;
    const logicalParent = `${base}/link`;
    rmSync(base, { recursive: true, force: true });
    mkdirSync(workspace, { recursive: true });
    mkdirSync(actualParent, { recursive: true });
    symlinkSync(actualParent, logicalParent);
    process.env.PI_CODING_AGENT_DIR = `${logicalParent}/missing/pi-agent`;

    const resolved = resolveSandboxPaths(workspace);
    expect(resolved.protectedRoots).toContain(resolve(realpathSync(actualParent), "missing/pi-agent"));
    expect(resolved.protectedRoots).toContain(resolve(logicalParent, "missing/pi-agent"));

    rmSync(base, { recursive: true, force: true });
  });
});

describe("sandboxShellArgsWithoutStartupFiles", () => {
  test("disables user startup files for supported shells", () => {
    expect(sandboxShellArgsWithoutStartupFiles("/bin/bash", ["-c"])).toEqual([
      "--noprofile",
      "--norc",
      "-c",
    ]);
    expect(sandboxShellArgsWithoutStartupFiles("/bin/zsh", ["-c"])).toEqual([
      "-f",
      "-c",
    ]);
    expect(sandboxShellArgsWithoutStartupFiles("/usr/local/bin/fish", ["-c"])).toEqual([
      "--no-config",
      "-c",
    ]);
    expect(sandboxShellArgsWithoutStartupFiles("/bin/sh", ["-c"])).toEqual(["-c"]);
  });
});

describe("resolveSandboxTimeoutMs", () => {
  test("matches Pi's positive finite timeout contract", () => {
    expect(resolveSandboxTimeoutMs(undefined)).toBeUndefined();
    expect(resolveSandboxTimeoutMs(1.5)).toBe(1_500);
    expect(() => resolveSandboxTimeoutMs(0)).toThrow("finite number");
    expect(() => resolveSandboxTimeoutMs(-1)).toThrow("finite number");
    expect(() => resolveSandboxTimeoutMs(Number.POSITIVE_INFINITY)).toThrow("finite number");
    expect(() => resolveSandboxTimeoutMs(3_000_000)).toThrow("maximum");
  });
});
