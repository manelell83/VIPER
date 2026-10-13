import { getToken } from "./auth";

const RECONNECT_DELAY_MS = 3000;
const WS_POLICY_VIOLATION = 1008;   // server closes with this code when auth fails
const MAX_RECONNECT_ATTEMPTS = 5;

export function createScanWebSocket(scanId, handlers = {}) {
  // Use same host/port as the frontend (Vite proxy routes /ws/* → backend)
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/${scanId}`;

  let ws = null;
  let reconnectAttempts = 0;
  let closed = false;

  function connect() {
    ws = new WebSocket(url);

    ws.onopen = () => {
      // Browsers cannot send an Authorization header on a WebSocket, so the
      // JWT is sent as the first message (never in the URL, which gets logged).
      ws.send(JSON.stringify({ type: "auth", token: getToken() }));
      reconnectAttempts = 0;
      handlers.onOpen?.();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handlers.onMessage?.(data);
      } catch {
        // ignore non-JSON frames (ping/pong)
      }
    };

    ws.onerror = (err) => handlers.onError?.(err);

    ws.onclose = (event) => {
      handlers.onClose?.(event);
      // Auto-reconnect on unexpected close (not user-initiated, not scan finished)
      if (!closed && reconnectAttempts < MAX_RECONNECT_ATTEMPTS
          && event.code !== 1000 && event.code !== WS_POLICY_VIOLATION) {
        reconnectAttempts++;
        setTimeout(connect, RECONNECT_DELAY_MS);
      }
    };
  }

  connect();

  return {
    send: (data) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify(data)),
    close: () => {
      closed = true;
      ws?.close(1000, "scan complete");
    },
    get readyState() { return ws?.readyState ?? WebSocket.CLOSED; },
  };
}
