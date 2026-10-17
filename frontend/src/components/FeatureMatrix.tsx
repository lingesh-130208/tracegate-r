import { useState } from "react";
import { featureCoverage, featureState } from "../lib/logic";
import type { AuditEvent, FeatureState, Mode } from "../types";

const stateLabel: Record<FeatureState, string> = {
  measured: "Measured",
  missing: "Missing",
  invalid: "Invalid",
  "not-reported": "Not reported",
};

interface FeatureMatrixProps {
  names: readonly string[];
  event: AuditEvent | null;
  mode: Mode;
}

export function FeatureMatrix({ names, event, mode }: FeatureMatrixProps) {
  const [selected, setSelected] = useState<number | null>(null);
  const coverage = featureCoverage(names, event);
  const selectedName = selected === null ? null : names[selected];
  const selectedStatus = selectedName ? featureState(selectedName, event) : null;
  const selectedValue = selectedName ? event?.features?.[selectedName] : undefined;

  return (
    <div className="feature-matrix-shell">
      <div className="feature-matrix" role="group" aria-label="Ordered 48-feature availability matrix">
        {names.map((name, index) => {
          const status = featureState(name, event);
          return (
            <button
              className={`feature-node state-${status}`}
              type="button"
              key={name}
              title={`${String(index + 1).padStart(2, "0")} · ${name} · ${stateLabel[status]}`}
              aria-label={`Feature ${index + 1}: ${name}. ${stateLabel[status]}.`}
              aria-pressed={selected === index}
              onClick={() => setSelected(index)}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
            </button>
          );
        })}
      </div>
      <div className="matrix-legend" aria-label="Feature status totals">
        <span><i className="legend-dot measured" />Measured <b>{coverage.measured}</b></span>
        <span><i className="legend-dot missing" />Missing <b>{coverage.missing}</b></span>
        <span><i className="legend-dot invalid" />Invalid <b>{coverage.invalid}</b></span>
        <span><i className="legend-dot not-reported" />Not reported <b>{coverage.notReported}</b></span>
      </div>
      <div className="feature-inspector" role="status" aria-live="polite">
        {selectedName && selectedStatus ? (
          <>
            <span className="feature-inspector-index">{String((selected ?? 0) + 1).padStart(2, "0")}</span>
            <span className="feature-inspector-name">{selectedName}</span>
            <span className={`state-pill state-${selectedStatus}`}>{stateLabel[selectedStatus]}</span>
            {selectedStatus === "measured" && typeof selectedValue === "number" && (
              <span className="feature-inspector-value">{selectedValue}</span>
            )}
          </>
        ) : (
          <span>{mode === "demo" ? "Select a node to inspect the synthetic example." : "Select a node. Without an audit record, feature values remain not reported."}</span>
        )}
      </div>
      <p className="matrix-caption">
        {mode === "demo"
          ? "DEMO DATA — synthetic example coverage; not live telemetry."
          : event
            ? `Availability from recorded event ${event.event_id}; no missing value is filled with zero.`
            : "Repository schema reference only. Live feature availability is not reported until an audit record is returned."}
      </p>
    </div>
  );
}
