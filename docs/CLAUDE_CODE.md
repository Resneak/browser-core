# Use Browser Core from Claude Code

For Claude Code, Codex and OpenCode installation paths, see [harness integration](HARNESSES.md).

Browser Core adds a native runtime recording to the tools Claude Code already uses. Continue using source inspection, Playwright, CDP, DevTools, hooks and server logs when those answer the question more directly.

Copy `.claude/skills/browser-core` into your project's `.claude/skills/` directory, or your personal Claude skills directory. Then ask Claude to use the browser core skill for a page you own or are authorized to inspect.

These locations follow the [Claude Code skill documentation](https://code.claude.com/docs/en/skills). You can invoke the skill directly as `/browser-core`.

Set `BROWSER_CORE_EXECUTABLE` and `BROWSER_CORE_WORKSPACE` in the terminal that starts Claude Code. Install the matching Python package in an environment available to that terminal.

## A useful investigation

1. Define a concrete question, such as which observed device reads belong to a generated function.
2. Record the shortest interaction that could answer it.
3. Read the collection receipt and focused call index.
4. Follow event sequence references in `events.jsonl` and retain the process, context and script identity.
5. Use DevTools for source text and network evidence. Confirm a claimed server outcome with the server itself.

The index is a starting point. It includes selected API families and can contain internal browser activity. Claude must not assume that every row belongs to the investigated page.
