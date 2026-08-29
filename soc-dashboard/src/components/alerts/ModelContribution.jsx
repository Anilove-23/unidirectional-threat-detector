import ScoreBar from '../common/ScoreBar';

/**
 * Visualizes model_source. Works identically for every threat class — the
 * three scores and fired_models list are always present in the contract,
 * so nothing here branches on threat_class.
 */
export default function ModelContribution({ modelSource }) {
  if (!modelSource) return null;
  return (
    <div className="space-y-3">
      <ScoreBar label="Supervised score" value={modelSource.supervised_score} color="#5B8DEF" />
      <ScoreBar label="Anomaly score" value={modelSource.anomaly_score} color="#B180F0" />
      <ScoreBar label="Sequence score" value={modelSource.sequence_score} color="#2DD4BF" />

      {modelSource.fired_models?.length > 0 && (
        <div className="pt-1">
          <span className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">Fired models</span>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {modelSource.fired_models.map((m) => (
              <span
                key={m}
                className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
              >
                {m}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
