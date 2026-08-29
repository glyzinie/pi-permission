import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  PERMISSION_EVENTS,
  PERMISSION_PROTOCOL_VERSION,
  type BashCommandNode,
  type BashStructuralAnalysis,
  type PermissionAnalyzer,
  type PermissionAnalyzerResult,
  type PermissionRequest,
  type RegisterAnalyzerEvent,
} from "./index.ts";

type Token =
  | { type: "word"; value: string; quoted: boolean; dynamic: boolean }
  | { type: "operator"; value: string };

const CONTROL_OPERATORS = new Set(["&&", "||", "|", "|&", ";", "&", "\n"]);
const REDIRECT_OPERATORS = new Set([
  ">",
  ">>",
  "<",
  "<<",
  "<<<",
  "&>",
  ">&",
  "<&",
]);

const LONG_OPERATORS = ["<<<", ";;&", "&&", "||", ">>", "<<", "|&", "&>", ">&", "<&", ";&"];

function isWhitespace(char: string): boolean {
  return char === " " || char === "\t" || char === "\r";
}

function tokenize(command: string): { tokens: Token[]; substitutions: string[]; warnings: string[] } {
  const tokens: Token[] = [];
  const substitutions: string[] = [];
  const warnings: string[] = [];

  let buffer = "";
  let quoted = false;
  let dynamic = false;
  let quote: "'" | '"' | undefined;
  let escaped = false;

  const flushWord = () => {
    if (buffer === "") return;
    tokens.push({ type: "word", value: buffer, quoted, dynamic });
    buffer = "";
    quoted = false;
    dynamic = false;
  };

  for (let i = 0; i < command.length; i += 1) {
    const char = command[i]!;
    const next = command[i + 1];

    if (escaped) {
      buffer += char;
      escaped = false;
      continue;
    }

    if (quote === "'") {
      if (char === "'") {
        quote = undefined;
        quoted = true;
      } else {
        buffer += char;
      }
      continue;
    }

    if (quote === '"') {
      if (char === '"') {
        quote = undefined;
        quoted = true;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        quoted = true;
        continue;
      }
      if (char === "$" || char === "`") {
        dynamic = true;
        substitutions.push(char === "`" ? "backtick" : "parameter-or-command");
      }
      buffer += char;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (char === "'" || char === '"') {
      quote = char;
      quoted = true;
      continue;
    }

    if (char === "#" && buffer === "") {
      while (i + 1 < command.length && command[i + 1] !== "\n") i += 1;
      continue;
    }

    if (char === "\n") {
      flushWord();
      tokens.push({ type: "operator", value: "\n" });
      continue;
    }

    if (isWhitespace(char)) {
      flushWord();
      continue;
    }

    if (char === "$" || char === "`") {
      dynamic = true;
      substitutions.push(char === "`" ? "backtick" : next === "(" ? "command" : "parameter");
      buffer += char;
      continue;
    }

    if (char === "*" || char === "?") {
      dynamic = true;
      substitutions.push("glob");
      buffer += char;
      continue;
    }

    const long = LONG_OPERATORS.find((candidate) => command.startsWith(candidate, i));
    if (long) {
      flushWord();
      tokens.push({ type: "operator", value: long });
      i += long.length - 1;
      continue;
    }

    if ("|;&><()".includes(char)) {
      // Preserve a numeric fd prefix such as 2> as part of the redirect operator.
      if ((char === ">" || char === "<") && /^\d+$/.test(buffer)) {
        const fd = buffer;
        buffer = "";
        quoted = false;
        dynamic = false;
        tokens.push({ type: "operator", value: `${fd}${char}` });
      } else {
        flushWord();
        tokens.push({ type: "operator", value: char });
      }
      continue;
    }

    buffer += char;
  }

  if (escaped) warnings.push("trailing escape");
  if (quote) warnings.push(`unterminated ${quote === "'" ? "single" : "double"} quote`);
  flushWord();

  return { tokens, substitutions, warnings };
}

function isRedirectOperator(value: string): boolean {
  if (REDIRECT_OPERATORS.has(value)) return true;
  return /^\d+(?:>|>>|<|<<)$/.test(value);
}

function isAssignment(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(value);
}

function buildAst(command: string): BashStructuralAnalysis {
  const { tokens, substitutions, warnings } = tokenize(command);
  const commands: BashCommandNode[] = [];
  const operators: string[] = [];

  let current: BashCommandNode = { argv: [], assignments: [], redirects: [] };
  let pendingRedirect: string | undefined;
  let background = false;
  let dynamic = substitutions.length > 0;

  const flushCommand = () => {
    if (
      current.argv.length === 0 &&
      current.assignments.length === 0 &&
      current.redirects.length === 0
    ) {
      return;
    }
    commands.push(current);
    current = { argv: [], assignments: [], redirects: [] };
  };

  for (const token of tokens) {
    if (token.type === "word") {
      dynamic ||= token.dynamic;
      if (pendingRedirect) {
        current.redirects.push({ operator: pendingRedirect, target: token.value });
        pendingRedirect = undefined;
        continue;
      }
      if (current.argv.length === 0 && isAssignment(token.value)) {
        current.assignments.push(token.value);
      } else {
        current.argv.push(token.value);
      }
      continue;
    }

    const operator = token.value;

    if (operator === "(" || operator === ")") {
      dynamic = true;
      operators.push(operator);
      continue;
    }

    if (isRedirectOperator(operator)) {
      if (pendingRedirect) {
        current.redirects.push({ operator: pendingRedirect });
        warnings.push(`redirect ${pendingRedirect} has no target`);
      }
      pendingRedirect = operator;
      continue;
    }

    if (CONTROL_OPERATORS.has(operator) || operator === ";&" || operator === ";;&") {
      if (pendingRedirect) {
        current.redirects.push({ operator: pendingRedirect });
        warnings.push(`redirect ${pendingRedirect} has no target`);
        pendingRedirect = undefined;
      }
      flushCommand();
      operators.push(operator);
      if (operator === "&") background = true;
      continue;
    }

    operators.push(operator);
    warnings.push(`unclassified shell operator: ${operator}`);
  }

  if (pendingRedirect) {
    current.redirects.push({ operator: pendingRedirect });
    warnings.push(`redirect ${pendingRedirect} has no target`);
  }
  flushCommand();

  return {
    raw: command,
    commands,
    operators,
    hasPipeline: operators.some((operator) => operator === "|" || operator === "|&"),
    background,
    dynamic,
    substitutions: [...new Set(substitutions)],
    warnings,
  };
}

const analyzer: PermissionAnalyzer = {
  id: "bash-structural",
  priority: 100,
  supports(request: PermissionRequest) {
    return request.toolName === "bash";
  },
  analyze(request): PermissionAnalyzerResult {
    const command = request.input.command;
    if (typeof command !== "string") {
      return {
        analyzer: "bash-structural",
        kind: "bash",
        data: {
          raw: "",
          commands: [],
          operators: [],
          hasPipeline: false,
          background: false,
          dynamic: false,
          substitutions: [],
          warnings: ["bash input.command is not a string"],
        } satisfies BashStructuralAnalysis,
        warnings: ["bash input.command is not a string"],
      };
    }

    const data = buildAst(command);
    return {
      analyzer: "bash-structural",
      kind: "bash",
      data,
      warnings: data.warnings,
    };
  },
};

export default function piPermissionAnalyzer(pi: ExtensionAPI) {
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
      (data as { protocolVersion?: unknown }).protocolVersion === PERMISSION_PROTOCOL_VERSION
    ) {
      register();
    }
  });

  register();
}
