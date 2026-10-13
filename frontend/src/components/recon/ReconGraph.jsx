import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import { CANVAS_BG, LABEL_COLOR, LABEL_FONT, EDGE_DEFAULT, SELECTED, safeDestroy } from "../../theme/graph";

// One colour per entity kind: domain -> subdomain -> IP -> service.
const NODE_COLORS = {
  domain:    { bg: "#3a2a0a", border: "#e0a52c" },
  subdomain: { bg: "#23202b", border: "#9b7bd4" },
  ip:        { bg: "#152430", border: "#4aa3c4" },
  service:   { bg: "#14241a", border: "#4ea86a" },
};

const STYLE = [
  {
    selector: "node",
    style: {
      width: 44, height: 44,
      "background-color": "data(bgColor)",
      "border-color": "data(borderColor)",
      "border-width": 2.5,
      label: "data(label)",
      "text-valign": "bottom", "text-halign": "center",
      "font-size": "9px", "font-family": LABEL_FONT, color: LABEL_COLOR,
      "text-margin-y": 6, "text-max-width": "130px", "text-wrap": "wrap",
    },
  },
  { selector: "node[type='domain']", style: { width: 62, height: 62, "border-width": 3, "font-weight": "bold" } },
  { selector: "node[unresolved='yes']", style: { "border-style": "dashed", opacity: 0.7 } },
  { selector: "node:selected", style: { "border-color": SELECTED, "border-width": 4 } },
  {
    selector: "edge",
    style: {
      width: 1.5, "line-color": EDGE_DEFAULT, "target-arrow-color": EDGE_DEFAULT,
      "target-arrow-shape": "triangle", "curve-style": "bezier", opacity: 0.8,
    },
  },
];

/** Renders the recon entity graph (domain → subdomains → IPs → services). */
export default function ReconGraph({ graph }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const layoutRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current || !graph) return;

    const nodes = (graph.nodes ?? []).map((n) => {
      const colors = NODE_COLORS[n.type] ?? NODE_COLORS.ip;
      return {
        data: {
          id: n.id, type: n.type, label: n.label,
          bgColor: colors.bg, borderColor: colors.border,
          unresolved: n.unresolved ? "yes" : "no",
          title: n.title ?? null, status: n.status ?? null,
        },
      };
    });
    const edges = (graph.edges ?? []).map((e, i) => ({
      data: { id: `e${i}`, source: e.source, target: e.target },
    }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: STYLE,
      minZoom: 0.2, maxZoom: 3, boxSelectionEnabled: false,
    });
    cyRef.current = cy;
    cy.container().style.background = CANVAS_BG;

    layoutRef.current = cy.layout({
      name: "breadthfirst", directed: true, roots: nodes.filter((n) => n.data.type === "domain").map((n) => n.data.id),
      animate: "end", animationDuration: 500, spacingFactor: 1.15, padding: 40, fit: true,
    });
    layoutRef.current.run();

    return () => { safeDestroy(cy, layoutRef.current); cyRef.current = null; layoutRef.current = null; };
  }, [graph]);

  return (
    <div className="relative">
      <div ref={containerRef} className="w-full rounded-xl" style={{ height: 420, background: CANVAS_BG }} />
      <div className="absolute bottom-3 left-3 flex flex-wrap gap-3 text-xs bg-black/30 rounded-lg px-3 py-1.5">
        {Object.entries({ domain: "Domain", subdomain: "Subdomain", ip: "IP", service: "Service" }).map(([k, label]) => (
          <span key={k} className="inline-flex items-center gap-1.5 text-tertiary">
            <span className="w-2.5 h-2.5 rounded-full inline-block"
                  style={{ background: NODE_COLORS[k].bg, border: `2px solid ${NODE_COLORS[k].border}` }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}
