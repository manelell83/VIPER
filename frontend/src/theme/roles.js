// Host roles for the topology: each gets a distinct colour and an in-node icon.
// Icons are built as inline-SVG data URIs (white stroke) so they render on the
// Cytoscape canvas over the role's colour. Roles are INFERRED from observed
// services, not certified.

// lucide-style 24x24 stroke paths.
const PATHS = {
  gateway: '<rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10V4"/><path d="M12 10a3 3 0 0 1 3-3 3 3 0 0 1 3 3"/>',
  web: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
  dns: '<path d="M18 6H5a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h13l4-3.5z"/><path d="M12 13v9"/><path d="M12 2v4"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>',
  file_sharing: '<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z"/>',
  remote_access: '<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>',
  workstation: '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
  unknown: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
};

// role -> { label, color (border/accent), bg (node fill) }
export const ROLE_META = {
  gateway:       { label: "Gateway / router",       color: "#e0a52c", bg: "#3a2a0a" },
  web:           { label: "Web server",             color: "#4aa3c4", bg: "#152430" },
  mail:          { label: "Mail server",            color: "#d08770", bg: "#3a241c" },
  dns:           { label: "DNS server",             color: "#8fbcbb", bg: "#16302e" },
  database:      { label: "Database",               color: "#b48ead", bg: "#2b2030" },
  file_sharing:  { label: "File sharing",           color: "#a3be8c", bg: "#1e2a18" },
  remote_access: { label: "Remote access / admin",  color: "#ebcb8b", bg: "#332a10" },
  workstation:   { label: "Workstation / host",     color: "#7690b0", bg: "#1e1d24" },
  unknown:       { label: "Unknown",                color: "#8a8a93", bg: "#1a1a1f" },
};

// Order shown in the legend (significance, gateway first).
export const ROLE_ORDER = ["gateway", "web", "mail", "dns", "database", "file_sharing", "remote_access", "workstation", "unknown"];

export function roleMeta(role) {
  return ROLE_META[role] ?? ROLE_META.unknown;
}

/** An inline-SVG data URI for a role's icon, stroked in `stroke` (default white). */
export function roleIconDataUri(role, stroke = "#f5f3ef") {
  const path = PATHS[role] ?? PATHS.unknown;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${path}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}
