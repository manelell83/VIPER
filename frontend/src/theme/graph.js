// Colours for the Cytoscape canvases (topology and attack graph).
// Cytoscape needs concrete colour values (it cannot read CSS variables), and
// graph canvases are always dark ("ink"), whatever the page theme, so these are
// the dark-theme values of the VIPER palette (see styles/tokens.css).

export const CANVAS_BG = "#0b0b0e";
export const LABEL_COLOR = "#d6d2cb";
export const LABEL_FONT = "JetBrains Mono, Consolas, monospace";
export const HIGHLIGHT = "#f5f3ef";
export const SELECTED = "#f0566b";
export const EDGE_DEFAULT = "#393842";

export const SEVERITY = {
  CRITICAL: { bg: "#5e1222", border: "#e4324f" },
  HIGH:     { bg: "#5a2614", border: "#ea7a45" },
  MEDIUM:   { bg: "#4a370a", border: "#cfa22c" },
  LOW:      { bg: "#2a3545", border: "#98abc4" },
};

/** Largest zoom applied automatically after a layout (keeps small graphs readable). */
export const MAX_AUTO_ZOOM = 1.3;

/**
 * Stop any running layout/animation, then destroy the Cytoscape instance.
 * Destroying while an animated layout is still running makes Cytoscape call
 * into a renderer that no longer exists ("Cannot read properties of null").
 */
export function safeDestroy(cy, layout) {
  try {
    layout?.stop();
    cy?.stop(true, true);
    cy?.elements().stop(true, true);
  } finally {
    cy?.destroy();
  }
}

/** After a layout has fitted the graph, cap the zoom and re-centre. */
export function capZoom(cy) {
  if (!cy || cy.destroyed()) return;
  if (cy.zoom() > MAX_AUTO_ZOOM) {
    cy.zoom(MAX_AUTO_ZOOM);
    cy.center();
  }
}
