import ScoreBar from '../common/ScoreBar';

export default function ModelContribution({ modelSource }) {
  if (!modelSource) return null;

  return (
    <div className="space-y-4">
      <div className="space-y-3 rounded-lg border border-border bg-surface-2/60 p-3.5">
        <ScoreBar label="Supervised Model (XGBoost)" value={modelSource.supervised_score} color="#3B7ADB" />
        <ScoreBar label="Anomaly Detection (IsoForest / AE)" value={modelSource.anomaly_score} color="#FBBF24" />
        <ScoreBar label="Sequential Deep Learning (LSTM)" value={modelSource.sequence_score} color="#34D399" />
      </div>

      {modelSource.fired_models?.length > 0 && (
        <div>
          <span className="text-2xs font-semibold uppercase tracking-wider text-ink-muted">Fired Models</span>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {modelSource.fired_models.map((m) => (
              <span
                key={m}
                className="rounded border border-border bg-surface-3 px-2 py-0.5 mono text-[11px] font-medium text-ink-secondary"
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
