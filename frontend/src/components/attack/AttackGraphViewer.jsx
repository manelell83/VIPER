import { useEffect, useRef, useState, useCallback } from "react";
import cytoscape from "cytoscape";
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Info } from "lucide-react";

// ── Node color mapping by type ───────────────────────────────────────────────
const NODE_STYLE = {
  ATTACKER: { bg: "#1a0000", border: "#ef4444", shape: "diamond", size: 80 },
  ENTRY:    { bg: "#7c2d12", border: "#f97316", shape: "diamond", size: 60 },
  PIVOT:    { bg: "#713f12", border: "#eab308", shape: "rectangle", size: 54 },
  TARGET:   { bg: "#450a0a", border: "#ef4444", shape: "ellipse", size: 54 },
  INTERNAL: { bg: "#0c1a2e", border: "#0ea5e9", shape: "ellipse", size: 48 },
};

// ── Edge color mapping by attack type ───────────────────────────────────────
const EDGE_COLORS = {
  REMOTE_ACCESS:        "#ef4444",
  LATERAL_MOVEMENT:     "#f97316",
  PRIVILEGE_ESCALATION: "#a855f7",
  DATA_ACCESS:          "#eab308",
  PERSISTENCE:          "#6b7280",
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
      "font-family": "Monaco, Consolas, monospace",
      color: "#d1d5db",
      "text-margin-y": 6,
      "text-max-width": "120px",
      "text-wrap": "ellipsis",
      shape: "data(shape)",
    },
  },
  {
    selector: "node[type='ATTACKER']",
    style: {
      "border-width": 3,
      "font-weight": "bold",
      color: "#fca5a5",
    },
  },
  {
    selector: "node.highlighted",
    style: {
      "border-width": 4,
      "border-color": "#ffffff",
      "z-index": 99,
    },
  },
  {
    selector: "node:selected",
    style: { "border-width": 4, "border-color": "#60a5fa" },
  },
  {
    selector: "edge",
    style: {
      width: "data(edgeWidth)",
      "line-color": "data(edgeColor)",
      "target-arrow-color": "data(edgeColor)",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      opacity: 0.8,
      "line-style": "data(lineStyle)",
    },
  },
  {
    selector: "edge.highlighted",
    style: { width: 4, opacity: 1, "z-index": 99 },
  },
  {
    selector: "edge:selected",
    style: { "border-width": 3 },
  },
];

const LEGEND = [
  { label: "External Attacker", ...NODE_STYLE.ATTACKER },
  { label: "Entry Point", ...NODE_STYLE.ENTRY },
  { label: "Pivot Host", ...NODE_STYLE.PIVOT },
  { label: "Target", ...NODE_STYLE.TARGET },
  { label: "Internal Host", ...NODE_STYLE.INTERNAL },
];

const EDGE_LEGEND = [
  { label: "Remote Access", color: EDGE_COLORS.REMOTE_ACCESS },
  { label: "Lateral Movement", color: EDGE_COLORS.LATERAL_MOVEMENT },
  { label: "Privilege Escalation", color: EDGE_COLORS.PRIVILEGE_ESCALATION },
  { label: "Data Access", color: EDGE_COLORS.DATA_ACCESS },
];


export default function AttackGraphViewer({ elements, onNodeSelect, highlightedPath }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selected, setSelected] = useState(null);
  const [showLegend, setShowLegend] = useState(true);

  // Init Cytoscape
  useEffect(() => {
    if (!containerRef.current) return;

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: [],
      style: AG_STYLE,
      layout: { name: "cose" },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.1,
      maxZoom: 5,
    });

    cyRef.current.on("tap", "node", (evt) => {
      const data = evt.target.data();
      setSelected(data);
      onNodeSelect?.(data);
    });

    cyRef.current.on("tap", "edge", (evt) => {
      setSelected({ _isEdge: true, ...evt.target.data() });
    });

    cyRef.current.on("tap", (evt) => {
      if (evt.target === cyRef.current) {
        setSelected(null);
        cyRef.current.elements().removeClass("highlighted");
      }
    });

    return () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, []);

  // Update elements when data changes
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !elements) return;

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
      const color = EDGE_COLORS[e.data.attack_type] ?? "#4b5563";
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

    cy.layout({
      name: "cose",
      animate: true,
      animationDuration: 700,
      nodeRepulsion: 12000,
      idealEdgeLength: 140,
      gravity: 0.25,
      numIter: 1000,
      fit: true,
      padding: 50,
    }).run();
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
    }
  }, [highlightedPath]);

  const zoom = (f) => cyRef.current?.zoom(cyRef.current.zoom() * f);
  const fit = () => cyRef.current?.fit(undefined, 50);
  const reset = () => { cyRef.current?.reset(); fit(); };

  const hasData = (elements?.nodes?.length ?? 0) > 0;

  return (
    <div
      className="relative w-full h-full rounded-xl overflow-hidden"
      style={{ background: "#0d0f14", border: "1px solid var(--color-border)" }}
    >
      {/* Controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button className="btn-icon glass" onClick={() => zoom(1.25)} title="Zoom In"><ZoomIn size={15} /></button>
        <button className="btn-icon glass" onClick={() => zoom(0.8)} title="Zoom Out"><ZoomOut size={15} /></button>
        <button className="btn-icon glass" onClick={fit} title="Fit"><Maximize2 size={15} /></button>
        <button className="btn-icon glass" onClick={reset} title="Reset"><RotateCcw size={15} /></button>
        <button
          className={`btn-icon glass ${showLegend ? "ring-1 ring-blue-500/50" : ""}`}
          onClick={() => setShowLegend((v) => !v)}
          title="Toggle Legend"
        >
          <Info size={15} />
        </button>
      </div>

      {/* Legend */}
      {showLegend && (
        <div className="absolute bottom-3 left-3 z-10 glass rounded-lg p-2.5 text-xs space-y-1.5 max-w-[180px]">
          <p className="text-muted font-semibold uppercase tracking-wider text-[10px] mb-2">Nodes</p>
          {LEGEND.map(({ label, border }) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-sm flex-shrink-0 border" style={{ background: "#1a1d29", borderColor: border }} />
              <span className="text-tertiary">{label}</span>
            </div>
          ))}
          <p className="text-muted font-semibold uppercase tracking-wider text-[10px] mt-2 mb-1">Attack Vectors</p>
          {EDGE_LEGEND.map(({ label, color }) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-5 h-0.5 flex-shrink-0" style={{ background: color }} />
              <span className="text-tertiary">{label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Cytoscape canvas */}
      <div ref={containerRef} className="w-full h-full" />

      {/* Node/edge tooltip */}
      {selected && (
        <div className="absolute top-3 left-3 z-10 glass rounded-xl p-3 max-w-[260px] animate-fadeIn">
          {selected._isEdge ? (
            <EdgeTooltip data={selected} />
          ) : (
            <NodeTooltip data={selected} />
          )}
        </div>
      )}

      {/* Empty state */}
      {!hasData && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-muted gap-3">
          <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1} opacity={0.2}>
            <polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2" />
            <line x1="12" y1="2" x2="12" y2="22" />
            <line x1="2" y1="8.5" x2="22" y2="8.5" />
            <line x1="2" y1="15.5" x2="22" y2="15.5" />
          </svg>
          <p className="text-sm">Select a completed scan to generate the attack graph</p>
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
        <span className="w-3 h-3 rounded-sm border flex-shrink-0" style={{ background: style.bg, borderColor: style.border }} />
        <p className="text-xs font-bold text-primary font-mono">{data.ip}</p>
      </div>
      {data.label !== data.ip && <p className="text-xs text-muted mb-1">{data.label}</p>}
      <div className="space-y-0.5">
        <p className="text-xs text-tertiary">Type: <span className="text-secondary">{data.type}</span></p>
        <p className="text-xs text-tertiary">Risk: <span className="font-bold" style={{ color: style.border }}>{data.risk_score?.toFixed(0)}/100</span></p>
        {data.vuln_count > 0 && (
          <p className="text-xs text-tertiary">CVEs: <span className="text-orange-400">{data.vuln_count}</span></p>
        )}
        {data.os && data.os !== "Unknown" && (
          <p className="text-xs text-tertiary">OS: <span className="text-secondary">{data.os}</span></p>
        )}
        {data.open_ports?.length > 0 && (
          <p className="text-xs text-tertiary">Ports: <span className="text-secondary">{data.open_ports.length} open</span></p>
        )}
      </div>
    </>
  );
}

function EdgeTooltip({ data }) {
  const color = EDGE_COLORS[data.attack_type] ?? "#6b7280";
  return (
    <>
      <div className="flex items-center gap-2 mb-2">
        <span className="w-5 h-0.5" style={{ background: color }} />
        <p className="text-xs font-bold text-primary">{data.attack_vector || data.attack_type}</p>
      </div>
      <div className="space-y-0.5">
        <p className="text-xs text-tertiary">Score: <span className="font-bold" style={{ color }}>{data.score?.toFixed(0)}/100</span></p>
        {data.port && <p className="text-xs text-tertiary">Port: <span className="font-mono text-secondary">{data.port}</span></p>}
        {data.cve_ids?.length > 0 && (
          <p className="text-xs text-tertiary">{data.cve_ids.length} CVE(s) linked</p>
        )}
        {data.description && (
          <p className="text-xs text-muted mt-1 leading-relaxed">{data.description}</p>
        )}
      </div>
    </>
  );
}
