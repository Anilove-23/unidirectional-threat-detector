export default function EmptyState({ title, description, icon = null }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      {icon}
      <p className="text-sm font-medium text-ink-secondary">{title}</p>
      {description && <p className="max-w-sm text-xs text-ink-muted">{description}</p>}
    </div>
  );
}
