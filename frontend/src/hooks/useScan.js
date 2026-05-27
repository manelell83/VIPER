import { useState, useRef, useCallback } from "react";
import { scanApi } from "../services/api";
import { createScanWebSocket } from "../services/websocket";

const initialState = {
  scanId: null,
  status: "idle",     // idle | starting | running | completed | failed
  progress: 0,
  message: "",
  hosts: [],
  logs: [],
  error: null,
  vulnCount: 0,
  vulnScanActive: false,
};

export function useScan() {
  const [state, setState] = useState(initialState);
  const wsRef = useRef(null);

  const _updateState = (patch) => setState((s) => ({ ...s, ...patch }));

  const _appendLog = (msg) =>
    setState((s) => ({ ...s, logs: [...s.logs.slice(-199), msg] }));

  const _connectWs = useCallback((scanId) => {
    wsRef.current?.close();

    wsRef.current = createScanWebSocket(scanId, {
      onOpen: () => _appendLog("WebSocket connected"),
      onClose: () => _appendLog("WebSocket closed"),
      onError: () => _updateState({ error: "WebSocket connection error" }),
      onMessage: (data) => {
        _appendLog(`[${data.type}] ${data.message || ""}`);

        switch (data.type) {
          case "started":
            _updateState({ status: "running", progress: 5 });
            break;

          case "progress":
            _updateState({
              message: data.message,
              progress: data.percent ?? state.progress,
            });
            break;

          case "arp_complete":
            _updateState({ progress: data.percent ?? 30, message: data.message });
            break;

          case "host_discovered":
            _updateState({
              progress: data.percent ?? state.progress,
              message: data.message,
            });
            break;

          case "host_scanned":
            setState((s) => ({
              ...s,
              progress: data.percent ?? s.progress,
              message: data.message,
              hosts: [
                ...s.hosts.filter((h) => h.ip !== data.data?.ip),
                data.data,
              ],
            }));
            break;

          case "vulnerability_scan_started":
            _updateState({ vulnScanActive: true, message: data.message });
            break;

          case "vulnerability_detected":
            setState((s) => ({ ...s, vulnCount: s.vulnCount + 1 }));
            break;

          case "vulnerability_scan_complete":
            _updateState({ vulnScanActive: false, message: data.message });
            break;

          case "completed":
            _updateState({
              status: "completed",
              progress: 100,
              message: data.message,
              vulnScanActive: false,
            });
            wsRef.current?.close();
            break;

          case "error":
            _updateState({ status: "failed", error: data.message, vulnScanActive: false });
            wsRef.current?.close();
            break;
        }
      },
    });
  }, []);

  const startNetworkScan = useCallback(async (interfaceName) => {
    setState({ ...initialState, status: "starting" });
    try {
      const res = await scanApi.startNetwork(interfaceName);
      _updateState({ scanId: res.scan_id, status: "running" });
      _connectWs(res.scan_id);
    } catch (err) {
      _updateState({ status: "failed", error: err.message });
    }
  }, [_connectWs]);

  const startDomainScan = useCallback(async (target) => {
    setState({ ...initialState, status: "starting" });
    try {
      const res = await scanApi.startDomain(target);
      _updateState({ scanId: res.scan_id, status: "running" });
      _connectWs(res.scan_id);
    } catch (err) {
      _updateState({ status: "failed", error: err.message });
    }
  }, [_connectWs]);

  const reset = useCallback(() => {
    wsRef.current?.close();
    setState(initialState);
  }, []);

  return { ...state, startNetworkScan, startDomainScan, reset };
}
