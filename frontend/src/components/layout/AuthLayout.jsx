import Logo from "../brand/Logo";

/** Two-column layout for the sign-in / sign-up pages: brand panel + form. */
export default function AuthLayout({ children }) {
  return (
    <div className="min-h-screen grid lg:grid-cols-2" style={{ background: "var(--bg)" }}>
      {/* Brand panel (always ink, whatever the theme) */}
      <aside className="section-ink hidden lg:flex flex-col justify-between p-12 relative overflow-hidden"
             style={{ borderRight: "1px solid var(--line)" }}>
        <Logo size={30} subtitle="Risk-based vuln analysis" />
        <div className="relative z-10">
          <p className="eyebrow mb-5">Find → assess → resolve</p>
          <p className="font-display font-bold max-w-md" style={{ fontSize: "2.4rem", lineHeight: 1.08, letterSpacing: "-0.03em" }}>
            Know which vulnerability to fix <span style={{ color: "var(--accent-text)" }}>first</span>.
          </p>
        </div>
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          Only scan systems you own or are explicitly authorised to test.
        </p>
        {/* Decorative oversized mark */}
        <svg viewBox="0 0 48 48" aria-hidden="true" className="absolute -right-24 -bottom-24 w-[28rem] opacity-[0.07]">
          <path d="M6 8H17L24 27L31 8H42L28.5 44L24 37L19.5 44Z" fill="var(--accent)" />
        </svg>
      </aside>

      {/* Form column */}
      <main className="flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-sm">{children}</div>
      </main>
    </div>
  );
}
