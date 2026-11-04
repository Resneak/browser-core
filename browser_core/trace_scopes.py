from __future__ import annotations


TRACE_CATEGORY_CONTRACT = "browser-core.trace-categories/8"
TRACE_CATEGORY_CONTRACTS = frozenset(
    {
        "browser-core.trace-categories/1",
        "browser-core.trace-categories/2",
        "browser-core.trace-categories/3",
        "browser-core.trace-categories/4",
        "browser-core.trace-categories/5",
        "browser-core.trace-categories/6",
        "browser-core.trace-categories/7",
        TRACE_CATEGORY_CONTRACT,
    }
)


TRACE_SCOPES: dict[str, tuple[str, ...]] = {
    "causal": ("browser_core.debug",),
    "causal-stream": ("browser_core.debug", "browser_core.stream"),
    "encoding": ("browser_core.debug", "blink.bindings.encoding"),
    "broad": (
        "browser_core.debug",
        "browser_core.stream",
        "blink.bindings",
        "blink.bindings.encoding",
    ),
    # V8's dedicated tagged category remains the existing opt-in scope.
    "source-identity": (
        "browser_core.debug",
        "browser_core.stream",
        "blink.bindings",
        "blink.bindings.encoding",
        "browser_core.source_identity",
    ),
    # The experimental Blink context event has its own dynamic opt-in gate.
    "source-context": (
        "browser_core.debug",
        "browser_core.stream",
        "blink.bindings",
        "blink.bindings.encoding",
        "browser_core.source_identity",
        "disabled-by-default-browser_core.source_context",
    ),
}

TRACE_SCOPES_V7 = {
    **TRACE_SCOPES,
    "source-context": (*TRACE_SCOPES["source-context"][:-1],
                       "disabled-by-default-blink.debug"),
}

# Contract 1 predates the dedicated stream category. Contract 2 split stream
# events from debug but still put every generated WebIDL entry in one category.
# New launches always publish contract 8; these maps only keep old session
# evidence readable under its exact originating contract.
TRACE_SCOPES_BY_CONTRACT: dict[str, dict[str, tuple[str, ...]]] = {
    "browser-core.trace-categories/1": {
        "causal": ("browser_core.debug",),
        "broad": ("browser_core.debug", "blink.bindings"),
    },
    "browser-core.trace-categories/2": {
        "causal": ("browser_core.debug",),
        "causal-stream": ("browser_core.debug", "browser_core.stream"),
        "broad": (
            "browser_core.debug",
            "browser_core.stream",
            "blink.bindings",
        ),
    },
    "browser-core.trace-categories/3": {
        "causal": ("browser_core.debug",),
        "causal-stream": ("browser_core.debug", "browser_core.stream"),
        "encoding": ("browser_core.debug", "blink.bindings.encoding"),
        "broad": (
            "browser_core.debug",
            "browser_core.stream",
            "blink.bindings",
            "blink.bindings.encoding",
        ),
    },
    "browser-core.trace-categories/4": {
        "causal": ("browser_core.debug",),
        "causal-stream": ("browser_core.debug", "browser_core.stream"),
        "encoding": ("browser_core.debug", "blink.bindings.encoding"),
        "broad": (
            "browser_core.debug",
            "browser_core.stream",
            "blink.bindings",
            "blink.bindings.encoding",
        ),
        "source-identity": (
            "browser_core.debug",
            "browser_core.stream",
            "blink.bindings",
            "blink.bindings.encoding",
            "disabled-by-default-v8.compile",
        ),
    },
    "browser-core.trace-categories/5": {
        "causal": ("browser_core.debug",),
        "causal-stream": ("browser_core.debug", "browser_core.stream"),
        "encoding": ("browser_core.debug", "blink.bindings.encoding"),
        "broad": (
            "browser_core.debug", "browser_core.stream",
            "blink.bindings", "blink.bindings.encoding",
        ),
        "source-identity": (
            "browser_core.debug", "browser_core.stream",
            "blink.bindings", "blink.bindings.encoding",
            "browser_core.source_identity",
        ),
    },
    "browser-core.trace-categories/6": {
        "causal": ("browser_core.debug",),
        "causal-stream": ("browser_core.debug", "browser_core.stream"),
        "encoding": ("browser_core.debug", "blink.bindings.encoding"),
        "broad": (
            "browser_core.debug", "browser_core.stream",
            "blink.bindings", "blink.bindings.encoding",
        ),
        "source-identity": (
            "browser_core.debug", "browser_core.stream",
            "blink.bindings", "blink.bindings.encoding",
            "browser_core.source_identity", "disabled-by-default-blink.debug",
        ),
    },
    "browser-core.trace-categories/7": TRACE_SCOPES_V7,
    TRACE_CATEGORY_CONTRACT: TRACE_SCOPES,
}


def valid_trace_categories(
    scope: str,
    contract: str | None = None,
) -> tuple[tuple[str, ...], ...]:
    if contract is not None:
        categories = TRACE_SCOPES_BY_CONTRACT.get(contract, {}).get(scope)
        return () if categories is None else (categories,)
    alternatives: list[tuple[str, ...]] = []
    for scopes in TRACE_SCOPES_BY_CONTRACT.values():
        categories = scopes.get(scope)
        if categories is not None and categories not in alternatives:
            alternatives.append(categories)
    return tuple(alternatives)
