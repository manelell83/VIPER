export function createScanWebSocket(scanId, handlers = {}) {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.hostname;
  const port = 8001; // backend port
  const url = `${protocol}://${host}:${port}/ws/${scanId}`;

  const ws = new WebSocket(url);

  ws.onopen = () => handlers.onOpen?.();

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handlers.onMessage?.(data);
    } catch {
      // ignore non-JSON frames
    }
  };

  ws.onerror = (err) => handlers.onError?.(err);

  ws.onclose = (event) => handlers.onClose?.(event);

  return {
    send: (data) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(data)),
    close: () => ws.close(),
    get readyState() { return ws.readyState; },
  };
}
