// Browser Core blocked-renderer calibration fixture.
//
// The loop is deliberately finite. A two-second CDP budget forces the page
// probe to time out while this top-level script is still inside
// V8ScriptRunner::RunCompiledScript; browser-process trace shutdown should then
// retain one open native execution scope without any page-to-server witness.
const browserCoreDeadline = Date.now() + 20_000;
while (Date.now() < browserCoreDeadline) {
  // Busy by design for the bounded native readback calibration.
}
