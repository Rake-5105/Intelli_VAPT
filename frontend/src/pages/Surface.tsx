/**
 * Attack surface visualization page with interactive SVG network topology.
 * Features auto-spaced multi-tier layout, pan/zoom, risk filtering, and node inspector.
 */
import { useMemo, useState } from "react";
import {
  Globe,
  Server,
  Bug,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Filter,
  CheckCircle,
} from "lucide-react";
import type { Surface as SurfaceType } from "../types";

type SurfaceProps = {
  surface: SurfaceType;
};

type FilterMode = "all" | "vulnerable" | "critical_high";

export function Surface({ surface }: SurfaceProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<FilterMode>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [zoomScale, setZoomScale] = useState(1);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Group nodes by type
  const rootNode = useMemo(
    () => surface.nodes.find((n) => n.type === "root") || { id: "internet", label: "Internet Scope", type: "root" },
    [surface.nodes]
  );

  const assetNodes = useMemo(
    () => surface.nodes.filter((n) => n.type === "asset"),
    [surface.nodes]
  );

  const findingNodes = useMemo(
    () => surface.nodes.filter((n) => n.type !== "root" && n.type !== "asset"),
    [surface.nodes]
  );

  // Map which findings belong to which asset
  const assetFindingMap = useMemo(() => {
    const map: Record<string, typeof findingNodes> = {};
    findingNodes.forEach((f) => {
      const edge = surface.edges.find((e) => e.target === f.id);
      const assetId = edge ? edge.source : "internet";
      if (!map[assetId]) map[assetId] = [];
      map[assetId].push(f);
    });
    return map;
  }, [surface.edges, findingNodes]);

  // Determine which assets have findings
  const vulnerableAssetIds = useMemo(() => new Set(Object.keys(assetFindingMap)), [assetFindingMap]);

  // Filtered lists based on user selection
  const displayedAssets = useMemo(() => {
    return assetNodes.filter((asset) => {
      // Search query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesName = asset.label.toLowerCase().includes(query);
        const hasMatchingFinding = (assetFindingMap[asset.id] || []).some((f) =>
          f.label.toLowerCase().includes(query)
        );
        if (!matchesName && !hasMatchingFinding) return false;
      }

      if (filterMode === "vulnerable") {
        return vulnerableAssetIds.has(asset.id);
      }

      if (filterMode === "critical_high") {
        const findings = assetFindingMap[asset.id] || [];
        return findings.some((f) => f.type === "critical" || f.type === "high");
      }

      return true;
    });
  }, [assetNodes, filterMode, searchQuery, vulnerableAssetIds, assetFindingMap]);

  const displayedFindings = useMemo(() => {
    const allowedAssetIds = new Set(displayedAssets.map((a) => a.id));
    return findingNodes.filter((f) => {
      const edge = surface.edges.find((e) => e.target === f.id);
      if (!edge) return allowedAssetIds.has("internet");
      return allowedAssetIds.has(edge.source);
    });
  }, [findingNodes, displayedAssets, surface.edges]);

  // Compute clean, spacious coordinates with zero overlap
  const { positions, width, height } = useMemo(() => {
    const pos: Record<
      string,
      {
        x: number;
        y: number;
        label: string;
        type: string;
        findingCount: number;
        highestSeverity?: string;
      }
    > = {};

    const assetCount = displayedAssets.length;

    // Grid configuration: 7 columns maximum for readability
    const cols = Math.min(7, Math.max(3, Math.ceil(Math.sqrt(assetCount * 1.8))));
    const colSpacing = 150; // ample horizontal breathing room
    const rowSpacing = 110; // ample vertical breathing room

    const totalWidth = Math.max(960, (cols + 1) * colSpacing);
    const startX = (totalWidth - (cols - 1) * colSpacing) / 2;

    // Root node at top center
    const rootX = totalWidth / 2;
    const rootY = 65;
    pos[rootNode.id] = {
      x: rootX,
      y: rootY,
      label: rootNode.label,
      type: "root",
      findingCount: findingNodes.length,
    };

    // Asset nodes placed in an orderly, spacious grid
    const assetStartY = 175;
    let maxAssetY = assetStartY;

    displayedAssets.forEach((asset, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);

      const x = startX + col * colSpacing;
      const y = assetStartY + row * rowSpacing;
      maxAssetY = Math.max(maxAssetY, y);

      const findings = assetFindingMap[asset.id] || [];
      const highestSeverity = findings.some((f) => f.type === "critical")
        ? "critical"
        : findings.some((f) => f.type === "high")
        ? "high"
        : findings.some((f) => f.type === "medium")
        ? "medium"
        : findings.some((f) => f.type === "low")
        ? "low"
        : findings.length > 0
        ? "informational"
        : undefined;

      pos[asset.id] = {
        x,
        y,
        label: asset.label,
        type: "asset",
        findingCount: findings.length,
        highestSeverity,
      };
    });

    // Place findings cascaded below their parent assets
    const findingStartY = maxAssetY + 120;
    let maxFindingY = findingStartY;

    // Distribute findings under their parent nodes or grouped row
    displayedFindings.forEach((finding, idx) => {
      const edge = surface.edges.find((e) => e.target === finding.id);
      const parentPos = edge && pos[edge.source] ? pos[edge.source] : null;

      let x: number;
      let y: number;

      if (parentPos && edge && filterMode !== "all") {
        // In focused modes, hang findings cleanly in columns below parent
        const siblings = assetFindingMap[edge.source] || [];
        const sIndex = siblings.findIndex((s) => s.id === finding.id);
        x = parentPos.x + (sIndex % 2 === 0 ? -35 : 35);
        y = parentPos.y + 70 + Math.floor(sIndex / 2) * 45;
      } else {
        // In all mode, place findings in a clean bottom shelf
        const fCols = Math.min(8, Math.max(4, Math.ceil(Math.sqrt(displayedFindings.length * 2))));
        const fCol = idx % fCols;
        const fRow = Math.floor(idx / fCols);
        const fSpacing = Math.min(130, totalWidth / (fCols + 1));
        const fStartX = (totalWidth - (fCols - 1) * fSpacing) / 2;
        x = fStartX + fCol * fSpacing;
        y = findingStartY + fRow * 65;
      }

      maxFindingY = Math.max(maxFindingY, y);

      pos[finding.id] = {
        x,
        y,
        label: finding.label,
        type: finding.type,
        findingCount: 0,
      };
    });

    const totalHeight = Math.max(520, maxFindingY + 90);

    return { positions: pos, width: totalWidth, height: totalHeight };
  }, [displayedAssets, displayedFindings, rootNode, findingNodes, assetFindingMap, filterMode, surface.edges]);

  // Color mapping
  const getColor = (type: string, isRing?: boolean) => {
    switch (type.toLowerCase()) {
      case "root":
        return "#83a598";
      case "critical":
        return "#fb4934";
      case "high":
        return "#fe8019";
      case "medium":
        return "#fabd2f";
      case "low":
        return "#b8bb26";
      case "informational":
        return "#83a598";
      case "asset":
        return isRing ? "#fabd2f" : "#8ec07b";
      default:
        return "#a89984";
    }
  };

  // Selected node details
  const selectedNode = selectedNodeId ? positions[selectedNodeId] : null;
  const selectedNodeFindings = selectedNodeId && assetFindingMap[selectedNodeId] ? assetFindingMap[selectedNodeId] : [];

  return (
    <section className="panel" style={{ padding: "20px 24px" }}>
      {/* Title & Stats */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, marginBottom: 16 }}>
        <div>
          <p className="eyebrow">ATTACK SURFACE MAPPING</p>
          <h2 style={{ fontSize: 22, marginTop: 4 }}>Asset and Network Topology</h2>
          <p className="muted" style={{ fontSize: 14, marginTop: 2 }}>
            Interactive scope visualization correlating discovered domains, host assets, and prioritized vulnerabilities.
          </p>
        </div>

        {/* Zoom & Reset Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: 6, padding: "4px 8px" }}>
          <button
            type="button"
            className="secondary"
            onClick={() => setZoomScale((z) => Math.min(1.8, z + 0.15))}
            title="Zoom In"
            style={{ padding: 6, border: 0, cursor: "pointer", display: "flex" }}
          >
            <ZoomIn size={16} />
          </button>
          <span style={{ fontSize: 13, fontWeight: 600, minWidth: 42, textAlign: "center", userSelect: "none" }}>
            {Math.round(zoomScale * 100)}%
          </span>
          <button
            type="button"
            className="secondary"
            onClick={() => setZoomScale((z) => Math.max(0.5, z - 0.15))}
            title="Zoom Out"
            style={{ padding: 6, border: 0, cursor: "pointer", display: "flex" }}
          >
            <ZoomOut size={16} />
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setZoomScale(1)}
            title="Reset Zoom"
            style={{ padding: 6, border: 0, cursor: "pointer", display: "flex" }}
          >
            <RotateCcw size={16} />
          </button>
        </div>
      </div>

      {/* Filter Tabs & Search Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, marginBottom: 14 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className={filterMode === "all" ? "" : "secondary"}
            onClick={() => setFilterMode("all")}
            style={{ fontSize: 13, padding: "6px 12px", borderRadius: 4, display: "flex", alignItems: "center", gap: 6 }}
          >
            <Filter size={13} /> All Assets ({assetNodes.length})
          </button>
          <button
            type="button"
            className={filterMode === "vulnerable" ? "" : "secondary"}
            onClick={() => setFilterMode("vulnerable")}
            style={{
              fontSize: 13,
              padding: "6px 12px",
              borderRadius: 4,
              display: "flex",
              alignItems: "center",
              gap: 6,
              borderColor: vulnerableAssetIds.size > 0 ? "var(--error)" : undefined,
            }}
          >
            <AlertTriangle size={13} color="var(--error)" /> Vulnerable Hosts ({vulnerableAssetIds.size})
          </button>
          <button
            type="button"
            className={filterMode === "critical_high" ? "" : "secondary"}
            onClick={() => setFilterMode("critical_high")}
            style={{ fontSize: 13, padding: "6px 12px", borderRadius: 4, display: "flex", alignItems: "center", gap: 6 }}
          >
            <Bug size={13} color="var(--orange)" /> High & Critical Risk
          </button>
        </div>

        {/* Quick Search */}
        <div style={{ position: "relative", minWidth: 240 }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
          <input
            type="text"
            placeholder="Search host or finding..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              padding: "6px 10px 6px 32px",
              fontSize: 13,
              background: "var(--bg-secondary)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              color: "var(--text-primary)",
            }}
          />
        </div>
      </div>

      {/* SVG Canvas Container */}
      <div
        style={{
          background: "var(--bg-secondary)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          overflow: "auto",
          maxHeight: "680px",
          position: "relative",
          boxShadow: "inset 0 1px 3px rgba(0,0,0,0.05)",
        }}
      >
        <div style={{ width: width * zoomScale, height: height * zoomScale, minWidth: "100%", transition: "width 0.2s, height 0.2s" }}>
          <svg
            viewBox={`0 0 ${width} ${height}`}
            style={{ width: "100%", height: "100%", display: "block" }}
          >
            <defs>
              {/* Subtle Drop Shadow for Circles */}
              <filter id="nodeShadow" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="0" dy="2" stdDeviation="2" floodOpacity="0.15" />
              </filter>
            </defs>

            {/* Render Connecting Edges (Smooth Curved Lines) */}
            {surface.edges.map((e, idx) => {
              const source = positions[e.source];
              const target = positions[e.target];
              if (!source || !target) return null;

              const isFromRoot = source.type === "root";
              const isSelectedEdge = selectedNodeId === e.source || selectedNodeId === e.target;

              // Quadratic Bezier curve for clean natural flow
              const midY = (source.y + target.y) / 2;
              const pathD = `M ${source.x} ${source.y} C ${source.x} ${midY}, ${target.x} ${midY}, ${target.x} ${target.y}`;

              return (
                <path
                  key={`edge-${idx}`}
                  d={pathD}
                  fill="none"
                  stroke={isSelectedEdge ? "var(--accent)" : isFromRoot ? "var(--border)" : "var(--border-light, #d0d7de)"}
                  strokeWidth={isSelectedEdge ? 2 : isFromRoot ? 1.5 : 1}
                  strokeDasharray={isFromRoot ? "4 4" : undefined}
                  opacity={isSelectedEdge ? 1 : isFromRoot ? 0.75 : 0.6}
                />
              );
            })}

            {/* Render Nodes */}
            {Object.entries(positions).map(([id, node]) => {
              const isSelected = selectedNodeId === id;
              const isHovered = hoveredNodeId === id;
              const isRoot = node.type === "root";
              const isAsset = node.type === "asset";
              const hasFindings = (node.findingCount || 0) > 0;

              // Size adjustments: neat, distinct radii
              const radius = isRoot ? 24 : isAsset ? (hasFindings ? 16 : 13) : 9;
              const color = node.highestSeverity ? getColor(node.highestSeverity) : getColor(node.type);

              // Clean truncated display label
              let displayLabel = node.label;
              if (isAsset) {
                // Extract clean subdomain prefix (e.g. "portal" from "portal.domain.com")
                const parts = node.label.split(".");
                displayLabel = parts.length > 2 ? parts[0] : node.label.substring(0, 11);
                if (displayLabel.length > 12) displayLabel = displayLabel.substring(0, 10) + "…";
              } else if (!isRoot && node.label.length > 15) {
                displayLabel = node.label.substring(0, 13) + "…";
              }

              return (
                <g
                  key={id}
                  onClick={() => setSelectedNodeId(id === selectedNodeId ? null : id)}
                  onMouseEnter={() => setHoveredNodeId(id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  style={{ cursor: "pointer", transition: "transform 0.2s" }}
                >
                  {/* Outer Pulsing Ring for Vulnerable Assets */}
                  {isAsset && hasFindings && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={radius + 4}
                      fill="none"
                      stroke={color}
                      strokeWidth="1.5"
                      strokeDasharray="3 3"
                      opacity="0.8"
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={radius}
                    fill="var(--bg-tertiary)"
                    stroke={isSelected ? "var(--accent)" : color}
                    strokeWidth={isSelected ? 3.5 : isAsset ? 2 : 1.5}
                    filter="url(#nodeShadow)"
                  />

                  {/* Inner Node Identifier / Icon */}
                  {isRoot ? (
                    <text
                      x={node.x}
                      y={node.y + 4}
                      textAnchor="middle"
                      fill="var(--text-primary)"
                      fontSize="11"
                      fontWeight="bold"
                      fontFamily="inherit"
                    >
                      ROOT
                    </text>
                  ) : isAsset && hasFindings ? (
                    <text
                      x={node.x}
                      y={node.y + 4}
                      textAnchor="middle"
                      fill={color}
                      fontSize="10"
                      fontWeight="bold"
                      fontFamily="inherit"
                    >
                      {node.findingCount}
                    </text>
                  ) : null}

                  {/* Node Label (Cleanly Positioned Beneath Circle) */}
                  <text
                    x={node.x}
                    y={node.y + radius + 14}
                    fill={isSelected ? "var(--accent)" : "var(--text-primary)"}
                    fontSize={isRoot ? "13" : isAsset ? "11" : "10"}
                    fontWeight={isRoot || isSelected ? "bold" : "500"}
                    textAnchor="middle"
                    fontFamily="inherit"
                  >
                    {displayLabel}
                  </text>

                  {/* Subtle Subtitle for Assets */}
                  {isAsset && (
                    <text
                      x={node.x}
                      y={node.y + radius + 25}
                      fill="var(--text-muted)"
                      fontSize="9"
                      textAnchor="middle"
                      fontFamily="inherit"
                    >
                      {hasFindings ? `${node.findingCount} finding${node.findingCount > 1 ? "s" : ""}` : "verified"}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Floating Node Inspector / Details Panel */}
        {selectedNode && (
          <div
            style={{
              position: "absolute",
              bottom: 16,
              right: 16,
              width: 320,
              maxHeight: 280,
              overflowY: "auto",
              background: "var(--bg-secondary)",
              border: "1px solid var(--accent)",
              borderRadius: 6,
              padding: 14,
              boxShadow: "0 8px 24px rgba(0,0,0,0.15)",
              fontSize: 13,
              zIndex: 10,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, borderBottom: "1px solid var(--border)", paddingBottom: 6 }}>
              <strong style={{ fontSize: 14, color: "var(--accent)" }}>Node Inspector</strong>
              <button
                type="button"
                onClick={() => setSelectedNodeId(null)}
                style={{ background: "none", border: 0, cursor: "pointer", color: "var(--text-muted)", fontSize: 16, padding: "0 4px" }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: "grid", gap: 6, color: "var(--text-secondary)" }}>
              <div>
                <strong>Label:</strong>{" "}
                <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>{selectedNode.label}</span>
              </div>
              <div>
                <strong>Type:</strong> <span style={{ textTransform: "capitalize" }}>{selectedNode.type}</span>
              </div>

              {selectedNode.type === "asset" && (
                <>
                  <div>
                    <strong>Correlated Findings:</strong>{" "}
                    <span style={{ color: selectedNodeFindings.length > 0 ? "var(--error)" : "var(--success)" }}>
                      {selectedNodeFindings.length} issue{selectedNodeFindings.length !== 1 ? "s" : ""}
                    </span>
                  </div>

                  {selectedNodeFindings.length > 0 && (
                    <div style={{ marginTop: 6 }}>
                      <p style={{ fontWeight: 600, color: "var(--text-primary)", marginBottom: 4 }}>Findings list:</p>
                      <ul style={{ margin: 0, paddingLeft: 16, display: "grid", gap: 4 }}>
                        {selectedNodeFindings.map((f) => (
                          <li key={f.id} style={{ fontSize: 12 }}>
                            <span style={{ color: getColor(f.type), fontWeight: "bold" }}>[{f.type.toUpperCase()}]</span>{" "}
                            {f.label}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Legend & Summary Info */}
      <div style={{ marginTop: 14, display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: 12, fontSize: 13 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 14, color: "var(--text-secondary)" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#83a598" }} /> Scope Root
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#8ec07b" }} /> Clean Host
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", border: "2px solid #fabd2f", background: "none" }} /> Vulnerable Host
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#fb4934" }} /> Critical Vuln
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#fe8019" }} /> High Risk
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#fabd2f" }} /> Medium Risk
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#b8bb26" }} /> Low / Info
          </span>
        </div>

        <div style={{ color: "var(--text-muted)", fontSize: 12 }}>
          Tip: Click any node to open the inspector, or use the filter tabs to focus on vulnerable hosts.
        </div>
      </div>
    </section>
  );
}
