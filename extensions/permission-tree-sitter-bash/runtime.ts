import { createRequire } from "node:module";

import {
  Language,
  Parser,
  type Tree,
} from "web-tree-sitter";

const BASH_GRAMMAR = "tree-sitter-bash.wasm";
const require = createRequire(import.meta.url);
let languagePromise: Promise<Language> | undefined;

function loadBashLanguage(): Promise<Language> {
  languagePromise ??= (async () => {
    await Parser.init();
    return Language.load(
      require.resolve(`tree-sitter-wasms/out/${BASH_GRAMMAR}`),
    );
  })();
  return languagePromise;
}

/** Parse Bash with deterministic cleanup. Tree-sitter nodes must not escape the callback. */
export async function withParsedBashTree<T>(
  source: string,
  fn: (tree: Tree) => T | Promise<T>,
): Promise<T> {
  const language = await loadBashLanguage();
  const parser = new Parser();
  let tree: Tree | null = null;
  try {
    parser.setLanguage(language);
    tree = parser.parse(source);
    if (!tree) throw new Error("tree-sitter failed to parse Bash");
    return await fn(tree);
  } finally {
    tree?.delete();
    parser.delete();
  }
}
