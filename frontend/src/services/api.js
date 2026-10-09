import axios from "axios";
import { getToken, clearSession } from "./auth";

const API = axios.create({
  baseURL: "/api",
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

// Attach the JWT to every request
API.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

API.interceptors.response.use(
  (r) => r.data,
  (err) => {
    // Token missing, expired or revoked → back to the login page
    if (err.response?.status === 401 && window.location.pathname !== "/login") {
      clearSession();
      window.location.assign("/login");
    }
    const detail = err.response?.data?.detail;
    // FastAPI validation errors (422) are a list of {loc, msg}; show their messages
    const msg = Array.isArray(detail)
      ? detail.map((d) => `${d.loc?.at(-1) ?? "field"}: ${d.msg}`).join(" · ")
      : detail || err.message || "Unknown error";
    return Promise.reject(new Error(typeof msg === "string" ? msg : "Invalid request"));
  }
);

export const authApi = {
  login: (username, password) => API.post("/auth/login", { username, password }),
  // Admin only (the backend returns 403 for analysts)
  createUser: (user) => API.post("/auth/users", user),
};

export const interfacesApi = {
  list: () => API.get("/interfaces"),
};

export const scanApi = {
  startNetwork: (interface_name) =>
    API.post("/scan/network", { interface: interface_name }),
  startDomain: (target) =>
    API.post("/scan/domain", { target }),
  status: (scanId) => API.get(`/scan/status/${scanId}`),
};

export const resultsApi = {
  list: () => API.get("/results"),
  get: (scanId) => API.get(`/results/${scanId}`),
  delete: (scanId) => API.delete(`/results/${scanId}`),
};

export const topologyApi = {
  get: (scanId) => API.get(`/topology/${scanId}`),
};

// A plain <a href> cannot send the Authorization header, so reports are
// fetched with the token and saved from an in-memory Blob.
async function downloadFile(path, filename) {
  const blob = await API.get(path, { responseType: "blob" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export const reportsApi = {
  downloadJson: (scanId) =>
    downloadFile(`/reports/export/${scanId}/json`, `viperv2_scan_${scanId.slice(0, 8)}.json`),
  downloadPdf: (scanId) =>
    downloadFile(`/reports/export/${scanId}/pdf`, `viperv2_report_${scanId.slice(0, 8)}.pdf`),
};

export default API;
