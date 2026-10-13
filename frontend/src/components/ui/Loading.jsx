export function Spinner({ size = 20, className = "" }) {
  return (
    <svg
      className={`animate-spin text-accent-text ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.5}
    >
      <circle cx="12" cy="12" r="10" strokeOpacity={0.25} />
      <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
    </svg>
  );
}

export function LoadingOverlay({ message = "Loading..." }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-tertiary">
      <Spinner size={36} />
      <p className="text-sm">{message}</p>
    </div>
  );
}

export function ProgressBar({ value = 0, animated = false }) {
  return (
    <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: "var(--color-border)" }}>
      {animated && value === 0 ? (
        <div className="h-full w-1/3 bg-accent rounded-full animate-progress" />
      ) : (
        <div
          className="h-full bg-accent rounded-full transition-all duration-500"
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
        />
      )}
    </div>
  );
}
