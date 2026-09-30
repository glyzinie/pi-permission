export type BashWriteTargetMode = "file" | "subtree";
export type BashControlOperator = "&&" | "||" | ";" | "|" | "|&" | "&";

export const BASH_ANALYSIS_KIND = "bash/tree-sitter" as const;
export const TREE_SITTER_BASH_PLUGIN_ID = "tree-sitter-bash" as const;

export interface BashStaticWord {
  raw: string;
  value?: string;
  /** True when any source fragment was quoted. */
  quoted: boolean;
  /** Bash performs tilde expansion only for an unquoted leading tilde. */
  expandTilde: boolean;
}

export interface BashRedirect {
  operator: string;
  fd?: string;
  target?: BashStaticWord;
  write: boolean;
}

export interface BashCommand {
  words: readonly BashStaticWord[];
  resolvedArgv?: readonly string[];
  assignments: readonly string[];
  redirects: readonly BashRedirect[];
  /** Whether intrinsic command effects are fully modeled; redirects are tracked separately. */
  effectsComplete: boolean;
}

export interface BashWriteTarget {
  path: BashStaticWord;
  mode: BashWriteTargetMode;
  operation: string;
}

export interface BashTreeSitterAnalysis {
  /** Exact command snapshot parsed by the analyzer. */
  raw: string;
  complete: boolean;
  dynamic: boolean;
  opaque: boolean;
  background: boolean;
  /** Explicit control operators in source order. Newlines are implicit sequences. */
  controlOperators: readonly BashControlOperator[];
  commands: readonly BashCommand[];
  writeTargets: readonly BashWriteTarget[];
  /** Every possible write destination is represented by writeTargets. */
  writeTargetsComplete: boolean;
  warnings: readonly string[];
}
