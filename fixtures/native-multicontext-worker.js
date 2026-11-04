addEventListener("message", (event) => {
  if (event.data !== "browser-core-port" || event.ports.length !== 1) return;
  event.ports[0].postMessage("browser-core-worker-port-ok");
}, { once: true });

async function exerciseWorkerContext() {
  const channel = new MessageChannel();
  const received = new Promise((resolve) => {
    channel.port2.onmessage = resolve;
  });
  channel.port1.postMessage({ role: "worker" });
  await received;

  await crypto.subtle.digest("SHA-256", new TextEncoder().encode("worker"));
  await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
  await exerciseBYOB();
  await exerciseBodyConsumers();
  await drain(await fetch("/probe?role=worker"));
  postMessage("browser-core-worker-ok");
}

exerciseWorkerContext();
async function drain(response) {
  const reader = response.body.getReader();
  while (!(await reader.read()).done) {}
}

async function exerciseBYOB() {
  const stream = new ReadableStream({
    type: "bytes",
    start(controller) {
      controller.enqueue(new Uint8Array([0x62, 0x63]));
      controller.close();
    },
  });
  const reader = stream.getReader({ mode: "byob" });
  const chunk = await reader.read(new Uint8Array(8));
  if (chunk.done || chunk.value.byteLength !== 2) {
    throw new Error("unexpected BYOB chunk");
  }
  const closed = await reader.read(new Uint8Array(8));
  if (!closed.done) throw new Error("BYOB stream did not close");
}

async function exerciseBodyConsumers() {
  const consumers = [
    () => new Response("array-buffer").arrayBuffer(),
    () => new Response("blob").blob(),
    () => new Response("bytes").bytes(),
    () => new Response("probe=body", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    }).formData(),
    () => new Response("{}").json(),
    () => new Response("text").text(),
  ];
  for (const consume of consumers) await consume();
}
