import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { ZoomIn, ZoomOut, Maximize2, RotateCcw } from "lucide-react";
import {
  CANVAS_BG, LABEL_COLOR, LABEL_FONT, SELECTED, EDGE_DEFAULT, SEVERITY,
  safeDestroy, capZoom,
} from "../../theme/graph";
import { ROLE_META, ROLE_ORDER, roleMeta, roleIconDataUri } from "../../theme/roles";

const CYTOSCAPE_STYLE = [
  {
    selector: "node",
    style: {
      width: 50,
      height: 50,
      "background-color": "data(bgColor)",
      "border-color": "data(borderColor)",
      "border-width": 2.5,
      "background-image": "data(icon)",
      "background-fit": "none",
      "background-width": "24px",
      "background-height": "24px",
      "background-clip": "none",
      label: "data(label)",
      "text-valign": "bottom",
      "text-halign": "center",
      "font-size": "10px",
      "font-family": LABEL_FONT,
      color: LABEL_COLOR,
      "text-margin-y": 8,
      "text-max-width": "160px",
      "text-wrap": "wrap",
      "text-background-color": CANVAS_BG,
      "text-background-opacity": 0.75,
      "text-background-padding": "2px",
      "text-background-shape": "roundrectangle",
      "transition-property": "background-color, border-color, width, height",
      "transition-duration": "200ms",
    },
  },
  {
    selector: "node[type='gateway']",
    style: { width: 62, height: 62, "border-width": 3, "font-weight": "bold", "background-width": "28px", "background-height": "28px" },
  },
  {
    selector: "node:selected",
    style: { "border-color": SELECTED, "border-width": 4, width: 58, height: 58 },
  },
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": EDGE_DEFAULT,
      "target-arrow-color": EDGE_DEFAULT,
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      opacity: 0.8,
    },
  },
  {
    selector: "edge:selected",
    style: { "line-color": SELECTED, "target-arrow-color": SELECTED, opacity: 1 },
  },
];

export default function TopologyViewer({ elements, onNodeClick }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const layoutRef = useRef(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: CYTOSCAPE_STYLE,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.2,
      maxZoom: 4,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const data = evt.target.data();
      setSelected(data);
      onNodeClick?.(data);
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) setSelected(null);
    });

    return () => {
      safeDestroy(cy, layoutRef.current);
      layoutRef.current = null;
      cyRef.current = null;
    };
  }, []);

  // Update elements when they change
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !elements) return;

    layoutRef.current?.stop();
    cy.elements().remove();

    const nodes = (elements.nodes ?? []).map((n) => {
      // Fill + icon come from the host's inferred role; the border shows CVE
      // severity when the host has vulnerabilities (role otherwise).
      const role = n.data.role ?? (n.data.type === "gateway" ? "gateway" : "unknown");
      const meta = roleMeta(role);
      const severity = n.data.type !== "gateway" ? n.data.max_severity : null;
      const sevColors = severity ? SEVERITY[severity] : null;
      return {
        ...n,
        data: {
          ...n.data,
          bgColor: meta.bg,
          borderColor: sevColors ? sevColors.border : meta.color,
          icon: roleIconDataUri(role),
          label: n.data.label + (n.data.vuln_count ? `\n${n.data.vuln_count} CVE${n.data.vuln_count > 1 ? "s" : ""}` : ""),
        },
      };
    });

    cy.add([...nodes, ...(elements.edges ?? [])]);

    const layout = cy.layout({
      name: "cose",
      // "end": positions are computed in one go, then nodes glide to them with a
      // normal Cytoscape animation that stop() can cancel (the "during" mode runs
      // its own frame loop that keeps going after the graph is destroyed).
      animate: "end",
      animationDuration: 600,
      nodeRepulsion: 8000,
      idealEdgeLength: 120,
      gravity: 0.3,
      numIter: 1000,
      fit: true,
      padding: 50,
    });
    layout.one("layoutstop", () => capZoom(cy));
    layoutRef.current = layout;
    layout.run();
  }, [elements]);

  // Every role present anywhere (including secondary roles of multi-role hosts).
  const presentRoles = new Set();
  for (const n of elements?.nodes ?? []) {
    (n.data.roles ?? [n.data.role]).filter(Boolean).forEach((r) => presentRoles.add(r));
  }

  const zoom = (factor) => cyRef.current?.zoom(cyRef.current.zoom() * factor);
  const fit = () => { cyRef.current?.fit(undefined, 50); capZoom(cyRef.current); };
  const reset = () => { cyRef.current?.reset(); fit(); };

  return (
    <div className="w-full h-full flex flex-col overflow-hidden"
         style={{ background: CANVAS_BG, border: "1px solid var(--line)", borderRadius: "var(--radius-lg)" }}>
      <div className="relative flex-1 min-h-0">
        {/* Controls */}
        <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
          <button className="btn-icon glass" onClick={() => zoom(1.25)} title="Zoom in" aria-label="Zoom in"><ZoomIn size={15} /></button>
          <button className="btn-icon glass" onClick={() => zoom(0.8)} title="Zoom out" aria-label="Zoom out"><ZoomOut size={15} /></button>
          <button className="btn-icon glass" onClick={fit} title="Fit to view" aria-label="Fit to view"><Maximize2 size={15} /></button>
          <button className="btn-icon glass" onClick={reset} title="Reset view" aria-label="Reset view"><RotateCcw size={15} /></button>
        </div>

        {/* Cytoscape canvas */}
        <div ref={containerRef} className="w-full h-full" />

        {/* Node details */}
        {selected && (
          <div className="absolute top-3 left-3 z-10 glass rounded-xl p-3 max-w-xs animate-fadeIn text-xs"
               style={{ background: "rgba(11, 11, 14, 0.9)", color: "#aaa5ad" }}>
            <p className="font-bold mb-1 font-mono" style={{ color: "#f5f3ef" }}>{selected.ip}</p>
            {selected.hostname && <p style={{ color: "#8d8a93" }}>{selected.hostname}</p>}
            {/* Inferred role(s) */}
            {selected.roles?.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1.5">
                {selected.roles.map((r) => (
                  <span key={r} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded"
                        style={{ background: roleMeta(r).bg, border: `1px solid ${roleMeta(r).color}`, color: "#d6d2cb" }}>
                    {roleMeta(r).label}
                  </span>
                ))}
              </div>
            )}
            {selected.os && <p className="mt-1.5">{selected.os}</p>}
            {selected.mac && <p className="font-mono mt-1" style={{ color: "#8d8a93" }}>{selected.mac}</p>}
            <p className="mt-1" style={{ color: "#98abc4" }}>{selected.open_ports ?? 0} open port(s)</p>
            {selected.vuln_count > 0 && (
              <p className="mt-0.5" style={{ color: "#ea7a45" }}>
                {selected.vuln_count} CVE{selected.vuln_count !== 1 ? "s" : ""}
                {selected.max_severity ? ` · ${selected.max_severity}` : ""}
              </p>
            )}
          </div>
        )}

        {/* Empty state */}
        {!elements?.nodes?.length && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2" style={{ color: "#8d8a93" }}>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} opacity={0.4} aria-hidden="true">
              <circle cx="12" cy="12" r="3" />
              <circle cx="3" cy="6" r="2" />
              <circle cx="21" cy="6" r="2" />
              <circle cx="3" cy="18" r="2" />
              <circle cx="21" cy="18" r="2" />
              <line x1="5" y1="6" x2="9.5" y2="11" />
              <line x1="19" y1="6" x2="14.5" y2="11" />
              <line x1="5" y1="18" x2="9.5" y2="13" />
              <line x1="19" y1="18" x2="14.5" y2="13" />
            </svg>
            <p className="text-sm">Run a scan to see the topology</p>
          </div>
        )}
      </div>

      {/* Legend strip (below the canvas, so it never hides nodes) */}
      <div className="px-4 py-3 text-xs" style={{ borderTop: "1px solid #26252d", color: "#aaa5ad" }}>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          {ROLE_ORDER.filter((r) => presentRoles.has(r)).map((r) => (
            <span key={r} className="inline-flex items-center gap-1.5" title={ROLE_META[r].label}>
              <img src={roleIconDataUri(r, ROLE_META[r].color)} alt="" width="13" height="13" aria-hidden="true" />
              {ROLE_META[r].label}
            </span>
          ))}
          <span className="w-px h-4" style={{ background: "#26252d" }} aria-hidden="true" />
          <span className="text-muted">Ring = CVE severity:</span>
          {Object.entries(SEVERITY).map(([sev, c]) => (
            <span key={sev} className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 rounded-full border-2" style={{ background: "transparent", borderColor: c.border }} aria-hidden="true" />
              {sev.charAt(0) + sev.slice(1).toLowerCase()}
            </span>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-muted">
          Roles are <span className="text-tertiary">inferred from observed services</span>, not certified
          (e.g. an open port 53 does not prove an authoritative DNS server). A host can hold several roles.
        </p>
      </div>
    </div>
  );
}
