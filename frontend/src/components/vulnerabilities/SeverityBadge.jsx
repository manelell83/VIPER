export const SEVERITY_CONFIG = {
  CRITICAL: { label: "Critical", className: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300", dot: "bg-red-500", ring: "ring-red-500" },
  HIGH:     { label: "High",     className: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300", dot: "bg-orange-500", ring: "ring-orange-500" },
  MEDIUM:   { label: "Medium",   className: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300", dot: "bg-yellow-500", ring: "ring-yellow-500" },
  LOW:      { label: "Low",      className: "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300", dot: "bg-blue-500", ring: "ring-blue-500" },
  NONE:     { label: "None",     className: "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400", dot: "bg-gray-400", ring: "ring-gray-400" },
};

export default function SeverityBadge({ severity, size = "sm" }) {
  const cfg = SEVERITY_CONFIG[severity?.toUpperCase()] ?? SEVERITY_CONFIG.NONE;
  const pulse = severity === "CRITICAL";

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-medium
      ${size === "lg" ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs"}
      ${cfg.className}`}
    >
      <span className={`rounded-full flex-shrink-0
        ${size === "lg" ? "w-2 h-2" : "w-1.5 h-1.5"}
        ${cfg.dot}
        ${pulse ? "animate-pulse" : ""}`}
      />
      {cfg.label}
    </span>
  );
}
