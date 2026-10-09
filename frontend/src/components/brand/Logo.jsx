// VIPER brand mark: a heavy geometric "V" whose tip splits into two fangs.
// Same path as public/viper.svg (favicon).
const MARK_PATH = "M6 8H17L24 27L31 8H42L28.5 44L24 37L19.5 44Z";

/** The mark alone. Colour defaults to the brand crimson. */
export function LogoMark({ size = 28, color = "var(--accent)", title = "VIPER" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" role="img" aria-label={title}>
      <path d={MARK_PATH} fill={color} />
    </svg>
  );
}

/**
 * Mark + wordmark. The wordmark uses the current text colour, so it works on
 * dark (ink) and light (cream) backgrounds alike.
 */
export default function Logo({ size = 28, subtitle }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <LogoMark size={size} />
      <span className="flex flex-col leading-none">
        <span
          className="font-display font-bold"
          style={{ fontSize: size * 0.68, letterSpacing: "0.18em", color: "var(--text)" }}
        >
          VIPER
        </span>
        {subtitle && (
          <span className="font-mono uppercase mt-1" style={{ fontSize: "0.6rem", letterSpacing: "0.14em", color: "var(--text-muted)" }}>
            {subtitle}
          </span>
        )}
      </span>
    </span>
  );
}
