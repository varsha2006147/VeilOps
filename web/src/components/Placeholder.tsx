export default function Placeholder({ className = '' }: { className?: string }) {
  return <span className={`placeholder ${className}`} aria-hidden="true">—</span>;
}
