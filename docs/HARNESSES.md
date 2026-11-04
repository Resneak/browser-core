# Claude Code, Codex and OpenCode

Browser Core is a local CLI. Each harness can run it through its shell tools, then read the same Markdown, JSON and HTML evidence. No special provider API or model is required. The Windows runtime and Python environment must be available on the machine executing those shell commands.

Set `BROWSER_CORE_EXECUTABLE` and `BROWSER_CORE_WORKSPACE` before launching the harness. Install the paired Python package in an environment available to it. See [setup](SETUP.md).

| Harness | Project skill location | How to use it |
| --- | --- | --- |
| Claude Code | `.claude/skills/browser-core/SKILL.md` | Ask for the browser core skill or invoke `/browser-core`. |
| Codex | `.agents/skills/browser-core/SKILL.md` | Ask to use `$browser-core`, or select it from skills. |
| OpenCode | `.agents/skills/browser-core/SKILL.md` | Ask it to load the `browser-core` skill. OpenCode also recognizes the included `.claude/skills` location. |

Copy the corresponding skill folder into the same location in the project you investigate. These instructions follow the official [Claude Code](https://code.claude.com/docs/en/skills), [Codex](https://learn.chatgpt.com/docs/build-skills), and [OpenCode](https://opencode.ai/docs/skills/) skill documentation.

## Example request

> Use Browser Core to record my local page at http://127.0.0.1:8000/. Investigate which observed canvas and device reads link to generated code. Use a fresh output directory, inspect recording health, and cite the exact process, context, script and event references. Use ordinary DevTools for source and network evidence. Separate observed calls from requests that were actually sent.

The skill helps the harness choose and interpret the CLI. It is not an MCP server and does not grant additional operating system permissions. Browser Core supplements the harness's normal browser tools.

## Evaluation scope

Harness compatibility and model effectiveness are different questions. A trial with one model in one harness does not establish the same improvement in the other harnesses. Any published evaluation must identify the actual harness, model, settings, baseline tools and task mix used.
