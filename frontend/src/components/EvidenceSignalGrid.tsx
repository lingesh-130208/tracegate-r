import type { ReactNode } from "react";

export interface SignalNode {
  id: string;
  title: string;
  subtitle: string;
  status: "verified" | "partial" | "unavailable" | "not-reported";
  detail: string;
  icon: ReactNode;
}

interface EvidenceSignalGridProps {
  nodes: SignalNode[];
  onSelect: (node: SignalNode) => void;
}

export function EvidenceSignalGrid({ nodes, onSelect }: EvidenceSignalGridProps) {
  return (
    <div className="signal-grid-wrap">
      <svg className="signal-grid-svg" viewBox="0 0 1000 190" role="group" aria-label="Evidence Signal Grid pipeline">
        <defs>
          <pattern id="signalDots" width="16" height="16" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.8" fill="currentColor" opacity="0.17" />
          </pattern>
        </defs>
        <rect x="0" y="0" width="1000" height="190" rx="18" fill="url(#signalDots)" />
        {nodes.slice(0, 4).map((node, index) => {
          const x = 116 + index * 192;
          const next = nodes[index + 1];
          const active = node.status === "verified" && next?.status === "verified";
          return (
            <line
              key={`path-${node.id}`}
              x1={x + 64}
              y1="82"
              x2={x + 128}
              y2="82"
              className={active ? "signal-path is-verified" : "signal-path"}
              aria-hidden="true"
            />
          );
        })}
        {nodes.map((node, index) => {
          const x = 52 + index * 192;
          return (
            <g
              key={node.id}
              className={`signal-node state-${node.status}`}
              role="button"
              tabIndex={0}
              aria-label={`${node.title}: ${node.subtitle}. Open system details.`}
              onClick={() => onSelect(node)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(node);
                }
              }}
            >
              <rect className="signal-card" x={x} y="38" width="142" height="88" rx="13" />
              <circle className="signal-status-ring" cx={x + 18} cy="56" r="4" />
              <text className="signal-title" x={x + 16} y="79">{node.title}</text>
              <text className="signal-subtitle" x={x + 16} y="99">{node.subtitle}</text>
              <text className="signal-index" x={x + 126} y="115">0{index + 1}</text>
            </g>
          );
        })}
        <text className="signal-footer" x="52" y="158">STATUS IS DERIVED FROM AVAILABLE API RESPONSES</text>
        <text className="signal-footer" x="948" y="158" textAnchor="end">NO COLLECTOR CONTROL</text>
      </svg>
      <div className="sr-only" aria-live="polite">Evidence pipeline stages are interactive. No data flow is animated.</div>
    </div>
  );
}
