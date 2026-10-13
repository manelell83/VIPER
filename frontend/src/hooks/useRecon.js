import { useCallback, useRef, useState } from "react";
import { reconApi } from "../services/api";
import { createScanWebSocket } from "../services/websocket";

const initialState = {
  reconId: null,
  status: "idle",     // idle | starting | running | completed | failed
  progress: 0,
  message: "",
  logs: [],
  result: null,
  error: null,
};

/** Drives a passive domain recon: starts it, streams progress over the shared
 *  WebSocket, and loads the full structured result when it completes. */
export function useRecon() {
  const [state, setState] = useState(initialState);
  const wsRef = useRef(null);

  const _update = (patch) => setState((s) => ({ ...s, ...patch }));
  const _log = (msg) => setState((s) => ({ ...s, logs: [...s.logs.slice(-199), msg] }));

  const _connect = useCallback((reconId) => {
    wsRef.current?.close();
    wsRef.current = createScanWebSocket(reconId, {
      onOpen: () => _log("WebSocket connected"),
      onClose: () => _log("WebSocket closed"),
      onError: () => _update({ error: "WebSocket connection error" }),
      onMessage: (data) => {
        _log(`[${data.type}] ${data.message || ""}`);
        switch (data.type) {
          case "started":
            _update({ status: "running", progress: 5 });
            break;
          case "completed":
            _update({ status: "completed", progress: 100, message: data.message });
            wsRef.current?.close();
            reconApi.get(reconId)
              .then((r) => _update({ result: r.result }))
              .catch((e) => _update({ error: e.message }));
            break;
          case "error":
            _update({ status: "failed", error: data.message });
            wsRef.current?.close();
            break;
          default:
            // progress, dns_complete, whois_complete, subdomains_complete, ...
            _update({ message: data.message ?? state.message, progress: data.percent ?? state.progress });
        }
      },
    });
  }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  const startRecon = useCallback(async (target) => {
    setState({ ...initialState, status: "starting" });
    try {
      const res = await reconApi.start(target);
      _update({ reconId: res.recon_id, status: "running" });
      _connect(res.recon_id);
    } catch (err) {
      _update({ status: "failed", error: err.message });
    }
  }, [_connect]);

  const reset = useCallback(() => {
    wsRef.current?.close();
    setState(initialState);
  }, []);

  return { ...state, startRecon, reset };
}
