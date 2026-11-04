"""Keep withdrawn Browser Core explanations withdrawn across current docs."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_gpu_noncompletion_docs_name_the_discriminator_not_a_mechanism() -> None:
    compared = _read("docs/COLLECTORS_COMPARED.md")
    improvement = _read("docs/WHERE_THIS_CAN_IMPROVE.md")
    prompt = _read("docs/GPT5_VERIFY_PROMPT.md")
    prompt_normalized = " ".join(prompt.split())
    combined = f"{compared}\n{improvement}\n{prompt}"

    assert "GPU mode was the observed discriminator on this host" in compared
    assert "the underlying mechanism remains unassigned" in compared
    assert "GPU mode is the measured method-axis difference on this host" in improvement
    assert "does not identify the mechanism" in improvement
    assert (
        "GPU mode was the retained discriminator; the mechanism remains unassigned"
        in prompt_normalized
    )
    assert "It is the GPU path, not headedness." not in combined
    assert "headless was only fast because it does not take that path" not in combined
    assert "the GPU did." not in prompt
    assert "headed/GPU mechanism is identified but not explained" not in prompt


def test_shape_packaging_observation_remains_withdrawn() -> None:
    compared = _read("docs/COLLECTORS_COMPARED.md")
    backlog = _read("docs/OVERNIGHT_IMPROVEMENT_BACKLOG.md")

    assert "floor is 11" in compared
    assert "`HTMLAudioElement.Audio` is in the volatile set" in compared
    assert "The finding it appeared to produce is\nwithdrawn." in compared
    assert "**The option is still right on fidelity grounds; the finding is withdrawn.**" in backlog


def test_startup_witness_cost_claim_remains_withdrawn() -> None:
    source = _read("browser_core/product_observation.py")
    backlog = _read("docs/OVERNIGHT_IMPROVEMENT_BACKLOG.md")

    assert "identical 121 names, symmetric difference 0" in source
    assert "The 7-name gap that\n#: prompted the change came from somewhere else" in source
    assert "Chasing a 7-name difference that was first blamed on the new witness" in backlog
    assert "Both witness spellings measure identically; the 7 names were never the instrument" in backlog


def test_unretained_poll_timing_is_not_presented_as_exact_evidence() -> None:
    improvement = _read("docs/WHERE_THIS_CAN_IMPROVE.md")
    source = _read("browser_core/product_observation.py")

    assert "no\npoll-timing artifact retained that exact sample" in improvement
    assert "not as an exact reproducible figure" in improvement
    assert "no retained artifact could establish it" in source


def test_desktop_device_memory_32_defect_claim_remains_withdrawn() -> None:
    backlog = _read("docs/OVERNIGHT_IMPROVEMENT_BACKLOG.md")

    assert "on a 64 GiB desktop **32 is the correct output**" in backlog
    assert "all on a secure origin" in backlog
    assert "**449 desktop personas at 32 are correct**" in backlog
    assert "**2,092 mobile personas at 32 are genuinely broken**" in backlog


def test_verification_prompt_dates_the_legacy_collection_checkpoint() -> None:
    prompt = " ".join(_read("docs/GPT5_VERIFY_PROMPT.md").split())

    assert (
        "at the continuing-branch audit checkpoint on 2026-08-09 it collected 1,147"
        in prompt
    )
    assert "continuing branch explicitly locks that legacy byte contract" in prompt
    assert "currently collects 1,147" not in prompt


def test_verification_prompt_keeps_the_b61_attribution_boundary_current() -> None:
    prompt = " ".join(_read("docs/GPT5_VERIFY_PROMPT.md").split())

    assert (
        "Current-script attribution on binding events was later closed under "
        "B61's calibrated native-trace contract"
        in prompt
    )
    assert "not source identity or semantic-value lineage" in prompt
    assert (
        "Seven scaffolded vendor trees were still unmeasured at the "
        "2026-08-09 checkpoint"
        in prompt
    )
    assert "script attribution on binding events is still unsolved" not in prompt
    assert "seven scaffolded vendor trees currently remain unmeasured" not in prompt


def test_verification_prompt_dates_the_observation_inventory_checkpoint() -> None:
    prompt = " ".join(_read("docs/GPT5_VERIFY_PROMPT.md").split())

    assert (
        "2026-08-09 audit checkpoint: 135 run directories plus 12 top-level "
        "JSON reports"
        in prompt
    )
    assert "not a current inventory" in prompt
    assert "Observation artifacts | Current snapshot:" not in prompt


def test_host_driven_guide_keeps_the_attribution_limitation_dated() -> None:
    guide = " ".join(_read("docs/HOST_DRIVEN_COLLECTORS.md").split())

    assert "What it could not do at the 2026-08-08 checkpoint" in guide
    assert "retained pre-B61 broad-scope binding events" in guide
    assert "B61's calibrated current-script count plane" in guide
    assert "not source identity or semantic-value lineage" in guide
    assert "What it still cannot do. Attribution stays the ceiling." not in guide


def test_re_use_cases_tracks_dispatch_and_callback_boundaries() -> None:
    use_cases = " ".join(_read("docs/RE_USE_CASES.md").split())
    architecture = " ".join(_read("docs/ARCHITECTURE.md").split())

    assert (
        "MessagePort dispatch-attempt correlation, direct WebIDL callback scopes "
        "and their exact native-Event handoff shipped"
        in use_cases
    )
    assert "Exact MessagePort callback handoff shipped" in use_cases
    assert "Architecture still open: message **delivery**" not in use_cases
    assert (
        "The initial linked 0.5.0 runtime predated patch 0010; the fully "
        "relinked and freshly attested runtime"
        in architecture
    )
    assert "Dispatch remains attempted-delivery evidence" in architecture
    assert (
        "The linked 0.5.0 runtime predates the patch, so this is source/object "
        "and staged-promotion evidence"
        not in architecture
    )


def test_architecture_does_not_infer_callback_realm_from_compiled_script_number() -> None:
    architecture = " ".join(_read("docs/ARCHITECTURE.md").split())

    assert "may carry a bounded V8 current-script number" in architecture
    assert "An earlier ScriptRun cannot resolve a later callback's realm" in architecture
    assert "native-binding-owner" in architecture
    assert "matching earlier ScriptRun supplies its exact context and script identity" not in architecture


def test_architecture_current_native_slice_lists_the_promoted_endpoints() -> None:
    architecture = " ".join(_read("docs/ARCHITECTURE.md").split())

    assert "The compiled ten-patch 0.5.0 slice covers" in architecture
    assert "MessagePort send and receiver dispatch attempt" in architecture
    assert "Body-consumption request markers" in architecture
    assert "explicit default/BYOB stream-read requests and results" in architecture
    assert "does not by itself prove listener execution or Body conversion completion" in architecture
    assert "Patch 0050 adds a distinct scoped callback anchor" in architecture
    assert "callback_script_identity_inherited" not in architecture
    assert "The compiled 0.5.0 slice covers script execution" not in architecture


def test_readme_tracks_messageport_runtime_promotion() -> None:
    readme = " ".join(_read("README.md").split())

    assert (
        "MessagePort dispatch-attempt correlation is fully linked, freshly "
        "attested, and live-verified in the owned fixture"
        in readme
    )
    assert (
        "join each retained dispatch to the exact "
        "`EventListener.handleEvent` invocation"
        in readme
    )
    assert "an unrelated nested Event listener is a passing negative control" in readme
    assert "Direct WebIDL callback invocation/return scope remains live-verified" in readme
    assert "MessagePort dispatch-attempt correlation is source/object-staged but not live" not in readme


def test_readme_keeps_binding_owner_and_unestablished_caller_separate() -> None:
    readme = " ".join(_read("README.md").split())

    assert "An earlier `ScriptRun` does not establish a later callback's realm" in readme
    assert "Caller identity remains unestablished" in readme
    assert "script-context-unresolved" in readme
    assert "callback-contained" in readme
    assert "not inherited from the callback function" in readme
    assert "matching earlier ScriptRun supplies its exact context" not in readme


def test_interface_documents_message_dispatch_attempt_handoff() -> None:
    interface = " ".join(_read("docs/INTERFACE.md").split())

    assert "message/MessagePort.message.dispatch" in interface
    assert "An explicit parent may cross renderer processes" in interface
    assert "message_parent_unavailable" in interface
    assert "message_parent_not_in_trace" in interface
    assert "not listener presence, handler execution or completion by itself" in interface
    assert "message_dispatch_parent_seq" in interface
    assert "message_dispatch_parent_not_in_trace" in interface
    assert "exact native Event held by the cited MessagePort dispatch" in interface
    assert "execution/host.callback.execution" in interface
    assert "callback_parent_seq" in interface
    assert "need not equal the callback function's ScriptId" in interface
    assert "--callback-edge-limit" in interface
    assert "edge_groups_truncated" in interface


def test_re_use_cases_counts_all_mandatory_observation_rules() -> None:
    use_cases = _read("docs/RE_USE_CASES.md")

    assert "Three rules that are not optional:" in use_cases
    assert "Two rules that are not optional:" not in use_cases
    assert use_cases.count("1. **Only control-subtracted surfaces are attributable.**") == 1
    assert use_cases.count("2. **Absent is not zero.**") == 1
    assert use_cases.count("3. **Read the fidelity verdict before the arguments.**") == 1
