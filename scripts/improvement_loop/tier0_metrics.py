"""Fixed fixture fact-coverage screen for one capped discovery response per arm.

The target facts are the owned Task A/B fixture facts in the supplied FINDINGS.md.
Only names and the recorded generated-code parent relation are scored here.
"""
import argparse
import json
from pathlib import Path


A_FACTS = (
    "Window.atob", "Navigator.hardwareConcurrency.get", "Screen.width.get",
    "Screen.height.get", "HTMLCanvasElement.getContext",
    "CanvasRenderingContext2D.fillText", "HTMLCanvasElement.toDataURL",
    "SubtleCrypto.digest", "Worker.constructor", "Worker.postMessage",
    "Worker.terminate", "Blob.constructor", "URL.createObjectURL", "fetch",
    "dynamic.code.materialized", "TextEncoder.encode",
)
B_APIS = (
    "Window.navigator.get", "Navigator.userAgent.get", "Window.screen.get",
    "Screen.colorDepth.get", "Window.performance.get", "Performance.now",
)
NOISE = {"promise.microtask.execution", "host.callback.execution"}
NOISE_PREFIXES = ("TreeWalker.", "Node.", "NodeList.", "Element.",
                  "CustomElementRegistry.")


def score(a: dict, b: dict, *, new: bool) -> dict:
    if new:
        a_names = {row["name"] for row in a["apis"]["groups"]}
        a_groups = a["apis"]["groups"]
        scripts = b["dynamic_scripts"]
        b_names = {row["name"] for script in scripts for row in script["apis"]}
        generated = {(row["pid"], row["generated_script_id"]) for row in scripts}
        nested = any(row["kind"] == "eval" and
                     (row["pid"], row["caller_script_id"]) in generated for row in scripts)
        noise = sum(row["class"] == "likely-internal-or-framework" for row in a_groups)
    else:
        a_groups = a["inventory"]["apis"]["groups"]
        a_names = {row["api"] for row in a_groups}
        b_names = set()
        materializations = b["events"]
        generated = {(row["process"]["pid"], row["detail"].get("generated_script_id"))
                     for row in materializations}
        nested = any(row["detail"].get("dynamic_kind") == "eval" and
                     (row["process"]["pid"], row["detail"].get("caller_script_id")) in generated
                     for row in materializations)
        noise = sum(row["api"] in NOISE or row["api"].startswith(NOISE_PREFIXES)
                    for row in a_groups)
    a_hit = sorted(set(A_FACTS) & a_names)
    b_hit = sorted(set(B_APIS) & b_names)
    return {"task_a": {"found": len(a_hit), "total": len(A_FACTS), "names": a_hit},
            "task_b": {"found": len(b_hit) + int(nested), "total": len(B_APIS) + 1,
                       "api_names": b_hit, "nested_generated_code": nested},
            "noise_top_groups": {"noisy": noise, "total": len(a_groups),
                                 "share": noise / len(a_groups) if a_groups else None}}


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("a_base", "b_base", "a_new", "b_new"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    def read(path):
        body = path.read_bytes()
        encoding = "utf-16" if body.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        return json.loads(body.decode(encoding))
    print(json.dumps({"base": score(read(args.a_base), read(args.b_base), new=False),
                      "new": score(read(args.a_new), read(args.b_new), new=True)}, indent=2))


if __name__ == "__main__":
    main()
