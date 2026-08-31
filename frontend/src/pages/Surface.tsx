/** Attack surface visualization page with interactive SVG network topology. */
import { useMemo, useState } from "react";
import type { Surface as SurfaceType } from "../types";

type SurfaceProps = {
  surface: SurfaceType;
};

export function Surface({ surface }: SurfaceProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  // Compute 2D node layout positions
  const layout = useMemo(() => {
    const rootNode = surface.nodes.find((n) => n.type === "root") || { id: "internet", label: "Internet", type: "root" };
    const assetNodes = surface.nodes.filter((n) => n.type === "asset");
    const findingNodes = surface.nodes.filter((n) => n.type !== "root" && n.type !== "asset");

    const positions: Record<string, { x: number; y: number; label: string; type: string }> = {};

    // Center root
    positions[rootNode.id] = { x: 400, y: 60, label: rootNode.label, type: rootNode.type };

    // Layout assets horizontally in row 2
    const assetCount = assetNodes.length || 1;
    assetNodes.forEach((node, i) => {
      const x = 150 + ((i + 1) * (500 / (assetCount + 1)));
      positions[node.id] = { x, y: 190, label: node.label, type: node.type };
    });

    // Layout findings grouped under their assets or below in row 3
    findingNodes.forEach((node, i) => {
      // Find edge pointing to this finding
      const edge = surface.edges.find((e) => e.target === node.id);
      const parentPos = edge && positions[edge.source] ? positions[edge.source] : null;
      
      const x = parentPos ? parentPos.x + ((i % 2 === 0 ? -1 : 1) * 60) : 100 + (i * 120);
      const y = 320 + ((i % 3) * 45);
      positions[node.id] = { x, y, label: node.label, type: node.type };
    });

    return positions;
  }, [surface]);

  const getColor = (type: string) => {
    switch (type) {
      case "root": return "#83a598";
      case "asset": return "#8ec07b";
      case "critical": return "#fb4934";
      case "high": return "#fe8019";
      case "medium": return "#fabd2f";
      case "low": return "#b8bb26";
      default: return "#a89984";
    }
  };

  return (
    <section className="panel">
      <p className="eyebrow">AUTHORIZED SCOPE CORRELATION</p>
      <h2>Asset and Attack Surface Topology</h2>
      <p className="muted" style={{ marginBottom: 16 }}>
        Interactive topology map illustrating authorization boundary to targets, live services, and correlated vulnerabilities.
      </p>

      <div style={{ background: "#1d2021", border: "1px solid #3c3836", borderRadius: 4, overflow: "hidden" }}>
        <svg viewBox="0 0 800 450" style={{ width: "100%", height: "auto", minHeight: 380 }}>
          {/* Render edges */}
          {surface.edges.map((e, idx) => {
            const source = layout[e.source];
            const target = layout[e.target];
            if (!source || !target) return null;
            return (
              <line
                key={`edge-${idx}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke="#504945"
                strokeWidth="2"
                strokeDasharray={source.type === "root" ? "4" : undefined}
              />
            );
          })}

          {/* Render nodes */}
          {Object.entries(layout).map(([id, node]) => {
            const color = getColor(node.type);
            const isSelected = selectedNode === id;
            return (
              <g
                key={id}
                onClick={() => setSelectedNode(id)}
                style={{ cursor: "pointer" }}
              >
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.type === "root" ? 22 : node.type === "asset" ? 18 : 14}
                  fill="#282828"
                  stroke={color}
                  strokeWidth={isSelected ? 4 : 2}
                />
                <text
                  x={node.x}
                  y={node.y + (node.type === "root" ? 34 : 28)}
                  fill="#ebdbb2"
                  fontSize="11"
                  textAnchor="middle"
                  fontFamily="inherit"
                >
                  {node.label.length > 20 ? node.label.substring(0, 18) + "…" : node.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div style={{ marginTop: 14, display: "flex", gap: 16, fontSize: 12, color: "#a89984" }}>
        <span><b style={{ color: "#83a598" }}>●</b> Origin Root</span>
        <span><b style={{ color: "#8ec07b" }}>●</b> Target Host</span>
        <span><b style={{ color: "#fb4934" }}>●</b> Critical</span>
        <span><b style={{ color: "#fe8019" }}>●</b> High</span>
        <span><b style={{ color: "#fabd2f" }}>●</b> Medium</span>
        <span><b style={{ color: "#b8bb26" }}>●</b> Low</span>
      </div>
    </section>
  );
}
