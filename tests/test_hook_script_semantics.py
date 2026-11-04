"""Execute the page-side instrument in Node and check what it actually does.

Until now the hook's JavaScript -- the riskiest part of `argument_capture`, and the
only code in this package that runs inside the observed page -- was exercised solely
by launching a real browser. That is slow, and on 2026-08-07 it became impossible:
the host stopped being able to bind loopback sockets, so *every* behavioural claim
about the instrument was untestable for the rest of the session.

The instrument is plain ES5 with no browser dependency beyond the objects it wraps,
so a handful of shims are enough to run it under Node and assert on
``__bcArgs.dump()``. That covers owner resolution (including the ``|`` alternatives),
argument classing, the value allowlist, the redaction denylist, install-time
self-suppression, the caps, and the shape the Python side parses -- in milliseconds,
with no browser and no socket.

Skipped, not failed, when Node is absent: a test that cannot run must say so.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap

import pytest

from browser_core.argument_capture import build_hook_script, parse_harvest

NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

# Minimal stand-ins for the Web IDL objects the instrument wraps. Deliberately
# hand-rolled rather than a DOM library: the point is to exercise the instrument,
# and anything it cannot find is reported as `prop-absent` rather than failing.
# Named function expressions on purpose. `X.prototype.foo = function () {}` leaves
# `.name` as the empty string -- ES6 name inference does not apply through a member
# expression -- whereas a real browser built-in reports its own name. Using
# anonymous functions here made the wrapper look like it was destroying `.name`
# when it was faithfully copying an empty one.
_SHIMS = """
globalThis.EventTarget = function EventTarget() {};
EventTarget.prototype.addEventListener =
  function addEventListener(type, fn, capture) { return 'added'; };
EventTarget.prototype.removeEventListener =
  function removeEventListener(type, fn) { return 'removed'; };

globalThis.Element = function Element() {};
Element.prototype.setAttribute = function setAttribute(name, value) {
  this[name] = value; return undefined;
};

globalThis.Storage = function Storage() {};
Storage.prototype.setItem = function setItem(k, v) { this['_' + k] = v; return undefined; };
Storage.prototype.getItem = function getItem(k) { return this['_' + k] || null; };
Storage.prototype.removeItem = function removeItem(k) { return undefined; };

globalThis.Window = function Window() {};
Window.prototype.matchMedia = function matchMedia(q) { return { matches: false, media: q }; };
Window.prototype.setTimeout = function setTimeout(fn, ms) { return 1; };

globalThis.WebGLRenderingContext = function WebGLRenderingContext() {};
WebGLRenderingContext.prototype.getParameter =
  function getParameter(e) { return 'SECRET_GPU_STRING'; };
WebGLRenderingContext.prototype.getExtension = function getExtension(n) { return null; };

globalThis.Permissions = function Permissions() {};
Permissions.prototype.query = function query(descriptor) {
  return { state: 'SECRET_HOST_ANSWER', descriptor: descriptor };
};
"""

_DRIVER = """
// A stand-in collector: does what a real one does, so the assertions have a
// known answer rather than whatever the sample happened to do.
var target = new EventTarget();
['mousemove', 'touchstart', 'devicemotion'].forEach(function (t) {
  target.addEventListener(t, function () {}, true);
});
target.addEventListener('mousemove', function () {}, true);  // duplicate -> count 2

var store = new Storage();
store.setItem('bm_sz', 'SECRET_VALUE_MUST_NOT_APPEAR');
store.getItem('bm_sz');

var win = new Window();
win.matchMedia('(pointer:coarse)');
win.setTimeout(function () {}, 21600000);

var gl = new WebGLRenderingContext();
gl.getParameter(37446);
gl.getParameter(37446);

var permissions = new Permissions();
permissions.query({ name: 'notifications', extra: 'SECRET_OBJECT_FIELD' });

var element = new Element();
element.setAttribute(
  'src',
  'https://user:SECRET_PASSWORD@challenges.cloudflare.com/' +
  'cdn-cgi/challenge-platform/widget-secret?lang=en&token=SECRET_QUERY_VALUE'
);
element.setAttribute('data-private', 'SECRET_ATTRIBUTE_VALUE');

Object.getOwnPropertyDescriptor(Storage.prototype, 'setItem');
Object.defineProperty({}, 'runtimePlaywright', { value: 1 });

// hook-detection probe: is this built-in native?
Function.prototype.toString.call(EventTarget.prototype.addEventListener);
"""


def _run_hook() -> dict:
    script = "\n".join(
        [_SHIMS, build_hook_script(), _DRIVER, "console.log(globalThis.__bcArgs.dump());"]
    )
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return parse_harvest(completed.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def harvest() -> dict:
    return _run_hook()


def _record(harvest: dict, name: str) -> dict | None:
    return next((r for r in harvest["records"] if r["name"] == name), None)


def _values(harvest: dict, name: str, index: int = 0) -> set:
    record = _record(harvest, name)
    if record is None:
        return set()
    return {
        json.dumps(s["args"][index]) for s in record["samples"] if len(s["args"]) > index
    }


def test_the_instrument_installs_and_produces_a_parseable_harvest(harvest):
    assert harvest["status"] == "ok"
    assert harvest["targets_installed"] > 0
    assert harvest["distinct_names"] > 0


def test_event_types_are_recorded_with_their_counts(harvest):
    record = _record(harvest, "EventTarget.addEventListener")
    assert record is not None
    assert record["calls"] == 4
    by_type = {json.loads(next(iter({json.dumps(s["args"][0])}))): s["count"]
               for s in record["samples"]}
    assert by_type == {"mousemove": 2, "touchstart": 1, "devicemotion": 1}


def test_a_storage_value_never_reaches_the_harvest(harvest):
    """The single most important property in the module."""
    assert "SECRET_VALUE_MUST_NOT_APPEAR" not in json.dumps(harvest)
    record = _record(harvest, "Storage.setItem")
    assert record is not None
    args = record["samples"][0]["args"]
    assert args[0] == "bm_sz", "the key is the finding and is kept"
    assert args[1] == "str(28)", "the value is reduced to a class"


def test_what_the_host_answered_is_not_recorded(harvest):
    """`getParameter` asks for the GPU; the answer is this machine's, not evidence."""
    assert "SECRET_GPU_STRING" not in json.dumps(harvest)
    assert _values(harvest, "WebGLRenderingContext.getParameter") == {"37446"}


def test_permission_descriptor_projects_only_its_name(harvest):
    rendered = json.dumps(harvest)
    assert "SECRET_HOST_ANSWER" not in rendered
    assert "SECRET_OBJECT_FIELD" not in rendered
    assert _values(harvest, "Permissions.query") == {'"permission:notifications"'}


def test_src_projection_retains_only_url_shape(harvest):
    rendered = json.dumps(harvest)
    for secret in (
        "SECRET_PASSWORD", "widget-secret", "SECRET_QUERY_VALUE",
        "SECRET_ATTRIBUTE_VALUE",
    ):
        assert secret not in rendered
    record = _record(harvest, "Element.setAttribute")
    assert record is not None
    samples = {tuple(sample["args"]): sample["count"] for sample in record["samples"]}
    assert samples[
        (
            "src",
            "url-shape:https://challenges.cloudflare.com|segments:7.18.13|query:lang,token",
        )
    ] == 1
    assert samples[("data-private", "str(22)")] == 1


def test_oversized_src_does_not_expand_url_parts_in_the_page():
    """A page-controlled URL must not force the hook to split a huge string."""
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var longPath = 'https://owned.example/' + 'a/'.repeat(50000);
            var longQuery = 'https://owned.example/?' + 'a=1&'.repeat(25000);
            var element = new Element();
            var originalSplit = String.prototype.split;
            String.prototype.split = function () {
              if (this.length > 16384) throw new Error('large split');
              return originalSplit.apply(this, arguments);
            };
            element.setAttribute('src', longPath);
            var preservedPath = element.src === longPath;
            element.setAttribute('src', longQuery);
            var preservedQuery = element.src === longQuery;
            String.prototype.split = originalSplit;
            console.log(JSON.stringify({
              preservedPath: preservedPath,
              preservedQuery: preservedQuery,
              harvest: globalThis.__bcArgs.dump()
            }));
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["preservedPath"] and result["preservedQuery"]
    harvest = parse_harvest(result["harvest"])
    record = _record(harvest, "Element.setAttribute")
    assert record is not None and record["calls"] == 2
    assert _values(harvest, "Element.setAttribute", 1) == {'"url-shape:oversize"'}


def test_string_cap_does_not_split_a_valid_unicode_character():
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var win = new Window();
            win.matchMedia('a'.repeat(119) + String.fromCodePoint(0x1F600));
            console.log(globalThis.__bcArgs.dump());
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    harvest = parse_harvest(completed.stdout.strip().splitlines()[-1])
    record = _record(harvest, "Window.matchMedia")
    assert record is not None
    assert record["samples"][0]["args"] == ["a" * 119 + "…"]


def test_numeric_arguments_keep_truthful_classes_and_json_safe_values():
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var win = new Window();
            win.setTimeout(function () {}, 2147483648);
            win.setTimeout(function () {}, Infinity);
            win.setTimeout(function () {}, -Infinity);
            win.setTimeout(function () {}, NaN);
            win.setTimeout(function () {}, 10000000000000000);
            win.setTimeout(function () {}, -0);
            var target = new EventTarget();
            target.addEventListener('x', 2147483648);
            console.log(globalThis.__bcArgs.dump());
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    harvest = parse_harvest(completed.stdout.strip().splitlines()[-1])
    assert _values(harvest, "Window.setTimeout", 1) == {
        "2147483648",
        '"number:+Infinity"',
        '"number:-Infinity"',
        '"number:NaN"',
        '"number:outside-safe-integer"',
        '"number:-0"',
    }
    assert _values(harvest, "EventTarget.addEventListener", 1) == {'"int"'}


def test_owner_alternatives_resolve_global_functions(harvest):
    """`matchMedia` lives on `Window.prototype`, not on the global object."""
    assert _values(harvest, "Window.matchMedia") == {'"(pointer:coarse)"'}
    assert _values(harvest, "Window.setTimeout", 1) == {"21600000"}


def test_the_instrument_does_not_record_its_own_installation(harvest):
    """Installing wrappers calls getOwnPropertyDescriptor and defineProperty.

    Before this guard existed, three findings were assembled entirely from the
    instrument observing itself.
    """
    assert harvest["self_calls_suppressed"] > 0
    descriptors = _values(harvest, "Object.getOwnPropertyDescriptor", 1)
    # Only the driver's own call survives; every install-time call is suppressed.
    assert descriptors == {'"setItem"'}
    defines = _values(harvest, "Object.defineProperty", 1)
    assert defines == {'"runtimePlaywright"'}
    assert '"__bcArgs"' not in defines, "the instrument recorded defining its own global"


def test_tostring_records_the_receiver_it_was_asked_about(harvest):
    assert _values(harvest, "Function.toString") == {'"<-addEventListener"'}


def test_wrapped_builtins_still_behave_like_the_originals():
    """An instrument that changes return values is not measuring the subject."""
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var t = new EventTarget();
            var s = new Storage();
            var w = new Window();
            var gl = new WebGLRenderingContext();
            console.log(JSON.stringify({
              add: t.addEventListener('x', function () {}, true),
              setItem: s.setItem('k', 'v'),
              getItem: s.getItem('k'),
              media: w.matchMedia('(a)').media,
              param: gl.getParameter(1),
              name: EventTarget.prototype.addEventListener.name,
              length: EventTarget.prototype.addEventListener.length
            }));
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["add"] == "added"
    assert result["getItem"] == "v"
    assert result["media"] == "(a)"
    assert result["param"] == "SECRET_GPU_STRING"
    assert result["name"] == "addEventListener", "wrapper must preserve name"
    assert result["length"] == 3, "wrapper must preserve arity"


def test_a_throwing_wrapper_never_breaks_the_sample():
    """A recording failure may lose a record; it must never lose a call."""
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var t = new EventTarget();
            // An argument whose inspection throws on every access.
            var hostile = new Proxy({}, { get: function () { throw new Error('no'); } });
            var out;
            try { out = t.addEventListener(hostile, hostile, hostile); }
            catch (e) { out = 'THREW: ' + e.message; }
            console.log(JSON.stringify({ out: out }));
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert json.loads(completed.stdout.strip().splitlines()[-1])["out"] == "added"


def test_the_per_name_sample_cap_is_enforced_in_the_page():
    """Bounds are enforced where the data is produced, not only on the way out."""
    script = "\n".join([
        _SHIMS,
        build_hook_script(),
        textwrap.dedent("""
            var t = new EventTarget();
            for (var i = 0; i < 500; i++) { t.addEventListener('e' + i, function () {}, true); }
            console.log(globalThis.__bcArgs.dump());
        """),
    ])
    completed = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    harvest = parse_harvest(completed.stdout.strip().splitlines()[-1])
    record = _record(harvest, "EventTarget.addEventListener")
    assert record["calls"] == 500, "every call is counted"
    assert len(record["samples"]) <= 200, "distinct values are capped"
    assert record["dropped"] > 0, "and the drop is reported, not hidden"
