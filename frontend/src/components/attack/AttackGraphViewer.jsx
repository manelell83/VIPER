import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Info } from "lucide-react";
import {
  CANVAS_BG, LABEL_COLOR, LABEL_FONT, HIGHLIGHT, SELECTED, EDGE_DEFAULT,
  safeDestroy, capZoom,
} from "../../theme/graph";

// ── Node style by type ───────────────────────────────────────────────────────
const NODE_STYLE = {
  ATTACKER: { bg: "#3a0913", border: "#e4324f", shape: "diamond",         size: 76 },
  ENTRY:    { bg: "#321208", border: "#ea7a45", shape: "diamond",         size: 60 },
  PIVOT:    { bg: "#2a1f04", border: "#cfa22c", shape: "round-rectangle", size: 54 },
  TARGET:   { bg: "#3a0913", border: "#c01f3c", shape: "ellipse",         size: 54 },
  INTERNAL: { bg: "#1a212c", border: "#7690b0", shape: "ellipse",         size: 48 },
};

// ── Edge colour by attack type ───────────────────────────────────────────────
const EDGE_COLORS = {
  REMOTE_ACCESS:        "#e4324f",
  LATERAL_MOVEMENT:     "#ea7a45",
  PRIVILEGE_ESCALATION: "#a77bd8",
  DATA_ACCESS:          "#cfa22c",
  PERSISTENCE:          "#8d8a93",
};

const AG_STYLE = [
  {
    selector: "node",
    style: {
      width: "data(nodeSize)",
      height: "data(nodeSize)",
      "background-color": "data(bgColor)",
      "border-color": "data(borderColor)",
      "border-width": 2,
      label: "data(label)",
      "text-valign": "bottom",
      "text-halign": "center",
      "font-size": "10px",
      "font-family": LABEL_FONT,
      color: LABEL_COLOR,
      "text-margin-y": 7,
      "text-max-width": "130px",
      "text-wrap": "wrap",
      shape: "data(shape)",
    },
  },
  {
    selector: "node[type='ATTACKER']",
    style: { "border-width": 3, "font-weight": "bold", color: "#f0566b" },
  },
  {
    selector: "node.highlighted",
    style: { "border-width": 4, "border-color": HIGHLIGHT, "z-index": 99 },
  },
  {
    selector: "node:selected",
    style: { "border-width": 4, "border-color": SELECTED },
  },
  {
    selector: "edge",
    style: {
      width: "data(edgeWidth)",
      "line-color": "data(edgeColor)",
      "target-arrow-color": "data(edgeColor)",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      opacity: 0.85,
      "line-style": "data(lineStyle)",
    },
  },
  {
    selector: "edge.highlighted",
    style: { width: 4, opacity: 1, "z-index": 99 },
  },
];

const LEGEND = [
  { label: "External attacker", ...NODE_STYLE.ATTACKER },
  { label: "Entry point", ...NODE_STYLE.ENTRY },
  { label: "Pivot host", ...NODE_STYLE.PIVOT },
  { label: "Target", ...NODE_STYLE.TARGET },
  { label: "Internal host", ...NODE_STYLE.INTERNAL },
];

const EDGE_LEGEND = [
  { label: "Remote access", color: EDGE_COLORS.REMOTE_ACCESS },
  { label: "Lateral movement", color: EDGE_COLORS.LATERAL_MOVEMENT, dashed: true },
  { label: "Privilege escalation", color: EDGE_COLORS.PRIVILEGE_ESCALATION },
  { label: "Data access", color: EDGE_COLORS.DATA_ACCESS },
];

export default function AttackGraphViewer({ elements, onNodeSelect, highlightedPath }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const layoutRef = useRef(null);
  const [selected, setSelected] = useState(null);
  const [showLegend, setShowLegend] = useState(true);

  // Init Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: AG_STYLE,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.1,
      maxZoom: 5,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const data = evt.target.data();
      setSelected(data);
      onNodeSelect?.(data);
    });

    cy.on("tap", "edge", (evt) => {
      setSelected({ _isEdge: true, ...evt.target.data() });
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelected(null);
        cy.elements().removeClass("highlighted");
      }
    });

    return () => {
      safeDestroy(cy, layoutRef.current);
      layoutRef.current = null;
      cyRef.current = null;
    };
  }, []);

  // Update elements when data changes
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !elements) return;

    layoutRef.current?.stop();
    cy.elements().remove();

    const nodes = (elements.nodes ?? []).map((n) => {
      const type = n.data.type ?? "INTERNAL";
      const style = NODE_STYLE[type] ?? NODE_STYLE.INTERNAL;
      return {
        ...n,
        data: {
          ...n.data,
          bgColor: style.bg,
          borderColor: style.border,
          nodeSize: style.size,
          shape: style.shape,
        },
      };
    });

    const edges = (elements.edges ?? []).map((e) => {
      const color = EDGE_COLORS[e.data.attack_type] ?? EDGE_DEFAULT;
      const isLateral = e.data.attack_type === "LATERAL_MOVEMENT" || e.data.attack_type === "PERSISTENCE";
      return {
        ...e,
        data: {
          ...e.data,
          edgeColor: color,
          edgeWidth: e.data.score >= 70 ? 3 : 2,
          lineStyle: isLateral ? "dashed" : "solid",
        },
      };
    });

    cy.add([...nodes, ...edges]);

    const layout = cy.layout({
      name: "cose",
      // "end": positions are computed in one go, then nodes glide to them with a
      // normal Cytoscape animation that stop() can cancel (the "during" mode runs
      // its own frame loop that keeps going after the graph is destroyed).
      animate: "end",
      animationDuration: 700,
      nodeRepulsion: 12000,
      idealEdgeLength: 140,
      gravity: 0.25,
      numIter: 1000,
      fit: true,
      padding: 60,
    });
    layout.one("layoutstop", () => capZoom(cy));
    layoutRef.current = layout;
    layout.run();
  }, [elements]);

  // Highlight attack path
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("highlighted");

    if (!highlightedPath?.path_node_ids?.length) return;

    const nodeIds = highlightedPath.path_node_ids;

    nodeIds.forEach((id) => {
      cy.$(`#${CSS.escape(id)}`).addClass("highlighted");
    });

    for (let i = 0; i < nodeIds.length - 1; i++) {
      cy.edges(`[source="${nodeIds[i]}"][target="${nodeIds[i + 1]}"]`).addClass("highlighted");
    }

    // Fit highlighted elements into view
    const highlighted = cy.$(".highlighted");
    if (highlighted.length) {
      cy.fit(highlighted, 80);
      capZoom(cy);
    }
  }, [highlightedPath]);

  const zoom = (f) => cyRef.current?.zoom(cyRef.current.zoom() * f);
  const fit = () => { cyRef.current?.fit(undefined, 60); capZoom(cyRef.current); };
  const reset = () => { cyRef.current?.reset(); fit(); };

  const hasData = (elements?.nodes?.length ?? 0) > 0;

  return (
    <div
      className="w-full h-full flex flex-col overflow-hidden"
      style={{ background: CANVAS_BG, border: "1px solid var(--line)", borderRadius: "var(--radius-lg)" }}
    >
      <div className="relative flex-1 min-h-0">
        {/* Controls */}
        <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
          <button className="btn-icon glass" onClick={() => zoom(1.25)} title="Zoom in" aria-label="Zoom in"><ZoomIn size={15} /></button>
          <button className="btn-icon glass" onClick={() => zoom(0.8)} title="Zoom out" aria-label="Zoom out"><ZoomOut size={15} /></button>
          <button className="btn-icon glass" onClick={fit} title="Fit to view" aria-label="Fit to view"><Maximize2 size={15} /></button>
          <button className="btn-icon glass" onClick={reset} title="Reset view" aria-label="Reset view"><RotateCcw size={15} /></button>
          <button
            className="btn-icon glass"
            onClick={() => setShowLegend((v) => !v)}
            title="Toggle legend"
            aria-label="Toggle legend"
            aria-pressed={showLegend}
          >
            <Info size={15} />
          </button>
        </div>

        {/* Cytoscape canvas */}
        <div ref={containerRef} className="w-full h-full" />

        {/* Node/edge details */}
        {selected && (
          <div className="absolute top-3 left-3 z-10 glass rounded-xl p-3 max-w-[260px] animate-fadeIn"
               style={{ background: "rgba(11, 11, 14, 0.85)" }}>
            {selected._isEdge ? <EdgeTooltip data={selected} /> : <NodeTooltip data={selected} />}
          </div>
        )}

        {/* Empty state */}
        {!hasData && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3" style={{ color: "#8d8a93" }}>
            <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1} opacity={0.35} aria-hidden="true">
              <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2" />
              <line x1="12" y1="2" x2="12" y2="22" />
              <line x1="2" y1="8.5" x2="22" y2="8.5" />
              <line x1="2" y1="15.5" x2="22" y2="15.5" />
            </svg>
            <p className="text-sm">Select a completed scan to generate the attack graph</p>
          </div>
        )}
      </div>

      {/* Legend strip (below the canvas, so it never hides nodes) */}
      {showLegend && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 text-xs"
             style={{ borderTop: "1px solid #26252d", color: "#aaa5ad" }}>
          {LEGEND.map(({ label, bg, border }) => (
            <span key={label} className="inline-flex items-center gap-2">
              <span className="w-3 h-3 rounded-sm border-2" style={{ background: bg, borderColor: border }} aria-hidden="true" />
              {label}
            </span>
          ))}
          <span className="w-px h-4" style={{ background: "#26252d" }} aria-hidden="true" />
          {EDGE_LEGEND.map(({ label, color, dashed }) => (
            <span key={label} className="inline-flex items-center gap-2">
              <span className="w-5" style={{ borderTop: `2px ${dashed ? "dashed" : "solid"} ${color}` }} aria-hidden="true" />
              {label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function NodeTooltip({ data }) {
  const style = NODE_STYLE[data.type] ?? NODE_STYLE.INTERNAL;
  return (
    <>
      <div className="flex items-center gap-2 mb-2">
        <span className="w-3 h-3 rounded-sm border-2 flex-shrink-0" style={{ background: style.bg, borderColor: style.border }} />
        <p className="text-xs font-bold font-mono" style={{ color: "#f5f3ef" }}>{data.ip}</p>
      </div>
      {data.label !== data.ip && <p className="text-xs mb-1" style={{ color: "#8d8a93" }}>{data.label}</p>}
      <div className="space-y-0.5 text-xs" style={{ color: "#aaa5ad" }}>
        <p>Type: <span style={{ color: "#d6d2cb" }}>{data.type}</span></p>
        <p>Risk: <span className="font-bold" style={{ color: style.border }}>{data.risk_score?.toFixed(0)}/100</span></p>
        {data.vuln_count > 0 && <p>CVEs: <span style={{ color: "#ea7a45" }}>{data.vuln_count}</span></p>}
        {data.os && data.os !== "Unknown" && <p>OS: <span style={{ color: "#d6d2cb" }}>{data.os}</span></p>}
        {data.open_ports?.length > 0 && <p>Ports: <span style={{ color: "#d6d2cb" }}>{data.open_ports.length} open</span></p>}
      </div>
    </>
  );
}

function EdgeTooltip({ data }) {
  const color = EDGE_COLORS[data.attack_type] ?? EDGE_DEFAULT;
  return (
    <>
      <div className="flex items-center gap-2 mb-2">
        <span className="w-5" style={{ borderTop: `2px solid ${color}` }} />
        <p className="text-xs font-bold" style={{ color: "#f5f3ef" }}>{data.attack_vector || data.attack_type}</p>
      </div>
      <div className="space-y-0.5 text-xs" style={{ color: "#aaa5ad" }}>
        <p>Score: <span className="font-bold" style={{ color }}>{data.score?.toFixed(0)}/100</span></p>
        {data.port && <p>Port: <span className="font-mono" style={{ color: "#d6d2cb" }}>{data.port}</span></p>}
        {data.cve_ids?.length > 0 && <p>{data.cve_ids.length} CVE(s) linked</p>}
        {data.description && <p className="mt-1 leading-relaxed" style={{ color: "#8d8a93" }}>{data.description}</p>}
      </div>
    </>
  );
}
