import { describe, expect, test } from "bun:test";

import permissionTreeSitterBash, {
  analyzeBashSource,
} from "../extensions/permission-tree-sitter-bash/index.ts";

describe("permission-tree-sitter-bash", () => {
  test("fails closed on non-string Bash input", async () => {
    let analyzer: any;
    permissionTreeSitterBash({
      events: {
        on() {},
        emit(_name: string, event: { analyzer?: unknown }) {
          if (event.analyzer) analyzer = event.analyzer;
        },
      },
    } as any);

    const result = await analyzer.analyze({ input: { command: 42 } });
    expect(result.data).toMatchObject({
      complete: false,
      dynamic: true,
      opaque: true,
      writeTargetsComplete: false,
    });
  });

  test("parses a static read-only command", async () => {
    const result = await analyzeBashSource("ls -la");
    expect(result.complete).toBe(true);
    expect(result.dynamic).toBe(false);
    expect(result.opaque).toBe(false);
    expect(result.controlOperators).toEqual([]);
    expect(result.commands[0]?.resolvedArgv).toEqual(["ls", "-la"]);
    expect(result.commands[0]?.effectsComplete).toBe(true);
    expect(result.writeTargetsComplete).toBe(true);
  });

  test("retains static control operators in source order", async () => {
    const result = await analyzeBashSource("printf ok | grep ok && echo done; true");
    expect(result).toMatchObject({
      complete: true,
      dynamic: false,
      opaque: false,
      background: false,
      controlOperators: ["|", "&&", ";"],
    });
    expect(result.commands.map((command) => command.effectsComplete)).toEqual([
      true,
      true,
      true,
      true,
    ]);

    const pipeAll = await analyzeBashSource("printf ok |& grep ok || false");
    expect(pipeAll.controlOperators).toEqual(["|&", "||"]);
  });

  test("does not prove expansions, assignments, or background execution safe", async () => {
    const assignment = await analyzeBashSource("PATH=/tmp ls");
    expect(assignment.dynamic).toBe(true);
    expect(assignment.writeTargetsComplete).toBe(false);

    const expansion = await analyzeBashSource("printf %s \"$VALUE\"");
    expect(expansion.dynamic).toBe(true);
    expect(expansion.writeTargetsComplete).toBe(false);

    const background = await analyzeBashSource("printf ok &");
    expect(background.background).toBe(true);
    expect(background.controlOperators).toEqual(["&"]);
  });

  test("preserves Bash tilde quote semantics", async () => {
    const unquoted = await analyzeBashSource("touch ~/.pi/agent/file");
    expect(unquoted.writeTargets[0]?.path).toMatchObject({
      value: "~/.pi/agent/file",
      expandTilde: true,
      quoted: false,
    });

    const quoted = await analyzeBashSource("touch '~/literal-file'");
    expect(quoted.writeTargets[0]?.path).toMatchObject({
      value: "~/literal-file",
      expandTilde: false,
      quoted: true,
    });
  });

  test("retains read redirects for credential policy", async () => {
    const result = await analyzeBashSource("cat < ~/.ssh/id_ed25519");
    expect(result.commands[0]?.redirects[0]).toMatchObject({
      operator: "<",
      write: false,
      target: { value: "~/.ssh/id_ed25519", expandTilde: true },
    });
  });

  test("associates redirects with their commands in static compositions", async () => {
    const result = await analyzeBashSource(
      "printf one > first.txt; cat < ~/.ssh/config; printf two >> second.txt",
    );
    expect(result.commands.map((command) => command.redirects)).toMatchObject([
      [{ operator: ">", target: { value: "first.txt" }, write: true }],
      [{ operator: "<", target: { value: "~/.ssh/config" }, write: false }],
      [{ operator: ">>", target: { value: "second.txt" }, write: true }],
    ]);
  });

  test("does not trust relative executable aliases or complex utilities", async () => {
    const relative = await analyzeBashSource("./cat file");
    const treeOutput = await analyzeBashSource("tree -o output.txt");
    const treeLongOutput = await analyzeBashSource("tree --output=output.txt");
    const fileCompile = await analyzeBashSource("file -C -m magic");
    const copy = await analyzeBashSource("cp source /outside/destination");
    expect(relative.writeTargetsComplete).toBe(false);
    expect(treeOutput.writeTargetsComplete).toBe(false);
    expect(treeLongOutput.writeTargetsComplete).toBe(false);
    expect(fileCompile.writeTargetsComplete).toBe(false);
    expect(copy.writeTargetsComplete).toBe(false);
  });

  test("treats shell state changes as opaque", async () => {
    for (const command of ["PATH=.; ls", "printf -v PATH .; ls", "cd; cat .ssh/id_ed25519"]) {
      const result = await analyzeBashSource(command);
      expect(result.opaque || result.dynamic).toBe(true);
      expect(result.writeTargetsComplete).toBe(false);
    }
  });

  test("fails closed on syntax errors", async () => {
    const result = await analyzeBashSource("if true; then");
    expect(result.complete).toBe(false);
    expect(result.writeTargetsComplete).toBe(false);
  });
});
