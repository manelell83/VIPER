const VARIANTS = {
  blue: "badge-blue",
  green: "badge-green",
  red: "badge-red",
  yellow: "badge-yellow",
  gray: "badge-gray",
  purple: "badge-purple",
};

const STATUS_MAP = {
  completed: "green",
  running: "blue",
  pending: "yellow",
  failed: "red",
  up: "green",
  down: "red",
};

export function Badge({ children, variant = "gray", className = "" }) {
  return (
    <span className={`badge ${VARIANTS[variant] ?? VARIANTS.gray} ${className}`}>
      {children}
    </span>
  );
}

export function StatusBadge({ status }) {
  const color = STATUS_MAP[status] ?? "gray";
  return (
    <Badge variant={color}>
      <span
        className={`w-1.5 h-1.5 rounded-full inline-block ${
          color === "green" ? "bg-green-500" :
          color === "blue" ? "bg-blue-500 animate-pulse" :
          color === "yellow" ? "bg-yellow-500" :
          color === "red" ? "bg-red-500" : "bg-gray-500"
        }`}
      />
      {status}
    </Badge>
  );
}
