import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { ZoomIn, ZoomOut, Maximize2, RotateCcw } from "lucide-react";

const NODE_COLORS = {
  gateway: { bg: "#f59e0b", border: "#d97706", text: "#1a1d29" },
  host: { bg: "#0ea5e9", border: "#0284c7", text: "#ffffff" },
  target: { bg: "#8b5cf6", border: "#7c3aed", text: "#ffffff" },
};

const CYTOSCAPE_STYLE = [
  {
    selector: "node",
    style: {
      width: 52,
      height: 52,
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
      "transition-property": "background-color, border-color, width, height",
      "transition-duration": "200ms",
    },
  },
  {
    selector: "node[type='gateway']",
    style: {
      width: 68,
      height: 68,
      "background-color": "#f59e0b",
      "border-color": "#d97706",
      "border-width": 3,
      "font-weight": "bold",
    },
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#0ea5e9",
      "border-width": 3,
      width: 64,
      height: 64,
    },
  },
  {
    selector: "edge",
    style: {
      width: 1.5,
      "line-color": "#374151",
      "target-arrow-color": "#374151",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      opacity: 0.7,
    },
  },
  {
    selector: "edge:selected",
    style: { "line-color": "#0ea5e9", "target-arrow-color": "#0ea5e9", opacity: 1 },
  },
];

export default function TopologyViewer({ elements, onNodeClick }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: [],
      style: CYTOSCAPE_STYLE,
      layout: { name: "cose", animate: false },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      minZoom: 0.2,
      maxZoom: 4,
    });

    cyRef.current.on("tap", "node", (evt) => {
      const node = evt.target;
      const data = node.data();
      setSelected(data);
      onNodeClick?.(data);
    });

    cyRef.current.on("tap", (evt) => {
      if (evt.target === cyRef.current) setSelected(null);
    });

    return () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, []);

  // Update elements when they change
  useEffect(() => {
    if (!cyRef.current || !elements) return;

    const cy = cyRef.current;
    cy.elements().remove();

    const nodes = (elements.nodes ?? []).map((n) => {
      const type = n.data.type ?? "host";
      const colors = NODE_COLORS[type] ?? NODE_COLORS.host;
      return {
        ...n,
        data: {
          ...n.data,
          bgColor: colors.bg,
          borderColor: colors.border,
        },
      };
    });

    cy.add([...nodes, ...(elements.edges ?? [])]);

    cy.layout({
      name: "cose",
      animate: true,
      animationDuration: 600,
      nodeRepulsion: 8000,
      idealEdgeLength: 120,
      gravity: 0.3,
      numIter: 1000,
      fit: true,
      padding: 40,
    }).run();
  }, [elements]);

  const zoom = (factor) => cyRef.current?.zoom(cyRef.current.zoom() * factor);
  const fit = () => cyRef.current?.fit(undefined, 40);
  const reset = () => { cyRef.current?.reset(); cyRef.current?.fit(undefined, 40); };

  return (
    <div className="relative w-full h-full rounded-xl overflow-hidden"
      style={{ background: "var(--color-topology-bg)", border: "1px solid var(--color-border)" }}>
      {/* Controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button className="btn-icon glass" onClick={() => zoom(1.25)} title="Zoom In"><ZoomIn size={15} /></button>
        <button className="btn-icon glass" onClick={() => zoom(0.8)} title="Zoom Out"><ZoomOut size={15} /></button>
        <button className="btn-icon glass" onClick={fit} title="Fit"><Maximize2 size={15} /></button>
        <button className="btn-icon glass" onClick={reset} title="Reset"><RotateCcw size={15} /></button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 z-10 glass rounded-lg p-2 text-xs space-y-1">
        {Object.entries(NODE_COLORS).map(([type, c]) => (
          <div key={type} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full inline-block border"
              style={{ background: c.bg, borderColor: c.border }} />
            <span className="text-tertiary capitalize">{type}</span>
          </div>
        ))}
      </div>

      {/* Cytoscape canvas */}
      <div ref={containerRef} className="w-full h-full" />

      {/* Node tooltip */}
      {selected && (
        <div className="absolute top-3 left-3 z-10 glass rounded-xl p-3 max-w-xs animate-fadeIn">
          <p className="text-xs font-bold text-primary mb-1 font-mono">{selected.ip}</p>
          {selected.hostname && <p className="text-xs text-muted">{selected.hostname}</p>}
          {selected.os && <p className="text-xs text-tertiary mt-1">{selected.os}</p>}
          {selected.mac && <p className="text-xs font-mono text-muted mt-1">{selected.mac}</p>}
          <p className="text-xs text-blue-400 mt-1">{selected.open_ports ?? 0} open port(s)</p>
        </div>
      )}

      {/* Empty state */}
      {!elements?.nodes?.length && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-muted gap-2">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} opacity={0.3}>
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
  );
}
