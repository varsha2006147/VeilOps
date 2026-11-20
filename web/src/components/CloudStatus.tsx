export default function CloudStatus({ error, lastUpdated, onRetry, message }: {
  error: boolean; lastUpdated: Date | null; onRetry?: () => void; message?: string;
}) {
  if (!error) return null;
  return <div className="cloud-status" role="status">
    {message ?? `Cloud unreachable — ${lastUpdated ? `showing last data from ${lastUpdated.toISOString().slice(11, 16)} UTC` : 'no data received yet'}`}
    {onRetry && <button onClick={onRetry}>Retry</button>}
  </div>;
}
