addEventListener("message", event => {
  if (event.data !== "bootstrap" || event.ports.length !== 1) return;
  const carrier=event.ports[0];
  carrier.onmessage = message => {
    const bytes=new Uint8Array(message.data.buffer);
    const valid=bytes.length===1024*1024 && bytes[0]===13 && bytes[bytes.length-1]===71;
    carrier.postMessage(valid ? "receiver-values-ok" : "receiver-values-failed");
    message.data.port.postMessage("receiver-port-ok");
    message.data.port.close();carrier.close();
  };
}, {once:true});
