import axios from "axios";

const API = axios.create({
  baseURL: "/api",
  timeout: 30000,
  headers: { "Content-Type": "application/json" },
});

API.interceptors.response.use(
  (r) => r.data,
  (err) => {
    const msg = err.response?.data?.detail || err.message || "Unknown error";
    return Promise.reject(new Error(msg));
  }
);

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

export const reportsApi = {
  exportJson: (scanId) => `/api/reports/export/${scanId}/json`,
  exportPdf: (scanId) => `/api/reports/export/${scanId}/pdf`,
};

export default API;
