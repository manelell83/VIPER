import { Link } from "react-router-dom";
import {
  Radar, Bug, Gauge, Waypoints, Activity, FileText, ArrowRight, Search, Scale, Wrench,
} from "lucide-react";
import Logo from "../components/brand/Logo";
import { getToken } from "../services/auth";

// Every feature listed here exists in the code base and was checked end to end.
const FEATURES = [
  {
    icon: Radar,
    title: "Host & service discovery",
    text: "ARP sweep on local networks and Nmap service/version detection on any IPv4 address or hostname you are authorised to test.",
  },
  {
    icon: Bug,
    title: "CVE correlation",
    text: "Detected products and versions are matched against the NIST National Vulnerability Database (NVD API 2.0), with CVSS scores.",
  },
  {
    icon: Gauge,
    title: "Risk-based prioritization",
    text: "Each host gets a 0–100 risk score from CVE severity and exposure, so the most dangerous issues rise to the top.",
  },
  {
    icon: Waypoints,
    title: "Attack-path graph",
    text: "A NetworkX graph links entry points and lateral movement, then ranks the paths an attacker would most likely take.",
  },
  {
    icon: Activity,
    title: "Live progress",
    text: "Scan events stream to the browser over an authenticated WebSocket while discovery, CVE lookup and analysis run.",
  },
  {
    icon: FileText,
    title: "PDF & JSON reports",
    text: "Export a complete assessment — executive summary, CVEs, attack paths and remediation plan — for each scan.",
  },
];

const STEPS = [
  { icon: Search, label: "Find", text: "Discover hosts and services, then correlate them with known CVEs." },
  { icon: Scale, label: "Assess", text: "Score each finding by CVSS, exposure and an exploit-maturity heuristic." },
  { icon: Wrench, label: "Resolve", text: "Get a remediation order: what to fix first, and why." },
];

export default function Landing() {
  const loggedIn = Boolean(getToken());

  return (
    <div className="min-h-screen section-ink">
      {/* ── Top bar ───────────────────────────────────────────────────── */}
      <header className="max-w-6xl mx-auto px-6 py-6 flex items-center justify-between">
        <Link to="/" aria-label="VIPER home"><Logo size={28} /></Link>
        <nav className="flex items-center gap-2" aria-label="Account">
          {loggedIn ? (
            <Link to="/app" className="btn-primary">Open dashboard <ArrowRight size={15} /></Link>
          ) : (
            <>
              <Link to="/login" className="btn-secondary">Sign in</Link>
              <Link to="/signup" className="btn-primary">Create an account</Link>
            </>
          )}
        </nav>
      </header>

      {/* ── Hero ──────────────────────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 pt-16 pb-20">
        <p className="eyebrow mb-6">Vulnerability analysis · Risk prioritization</p>
        <h1
          className="font-display font-bold max-w-4xl"
          style={{ fontSize: "var(--text-display)", lineHeight: 1.02, letterSpacing: "-0.035em" }}
        >
          Find what&apos;s exposed.{" "}
          <span style={{ color: "var(--accent-text)" }}>Fix what matters first.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg" style={{ color: "var(--text-2)" }}>
          VIPER scans the networks you are authorised to test, correlates every exposed
          service with known CVEs, scores the risk and maps the attack paths — so
          remediation starts with what an attacker would exploit first.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-3">
          {loggedIn ? (
            <Link to="/app" className="btn-primary text-base px-6 py-3">Open dashboard <ArrowRight size={16} /></Link>
          ) : (
            <>
              <Link to="/login" className="btn-primary text-base px-6 py-3">Sign in <ArrowRight size={16} /></Link>
              <Link to="/signup" className="btn-secondary text-base px-6 py-3">Create an account</Link>
            </>
          )}
        </div>

        {/* Dashboard preview: a real screenshot of the app after a scan of 127.0.0.1 */}
        <figure className="mt-16">
          <div
            className="overflow-hidden"
            style={{
              borderRadius: "var(--radius-xl)",
              border: "1px solid var(--line)",
              boxShadow: "0 40px 120px -40px rgba(192, 31, 60, 0.35), var(--shadow-lg)",
            }}
          >
            <img
              src="/landing/dashboard.png"
              alt="VIPER dashboard after a scan: scan counts, security score, vulnerability overview and recent scans"
              className="block w-full h-auto"
              width="1440"
              height="900"
            />
          </div>
          <figcaption className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>
            Screenshot of the VIPER dashboard after a real scan of a lab machine.
          </figcaption>
        </figure>
      </section>

      {/* ── Features (cream section) ──────────────────────────────────── */}
      <section className="section-cream" id="features">
        <div className="max-w-6xl mx-auto px-6 py-24">
          <p className="eyebrow mb-4">What it does</p>
          <h2 className="font-display font-bold max-w-2xl" style={{ fontSize: "var(--text-3xl)", letterSpacing: "-0.03em" }}>
            From a raw scan to a ranked list of priorities.
          </h2>
          <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <article key={title} className="card">
                <span
                  className="inline-flex w-10 h-10 items-center justify-center rounded-xl"
                  style={{ background: "var(--accent-soft)", color: "var(--accent-text)" }}
                >
                  <Icon size={20} aria-hidden="true" />
                </span>
                <h3 className="section-title mt-5">{title}</h3>
                <p className="mt-2 text-sm" style={{ color: "var(--text-3)" }}>{text}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ──────────────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-6 py-24" id="how-it-works">
        <p className="eyebrow mb-4">How it works</p>
        <h2 className="font-display font-bold max-w-2xl" style={{ fontSize: "var(--text-3xl)", letterSpacing: "-0.03em" }}>
          Find → assess → resolve.
        </h2>
        <ol className="mt-14 grid gap-5 md:grid-cols-3">
          {STEPS.map(({ icon: Icon, label, text }, i) => (
            <li key={label} className="card">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm" style={{ color: "var(--text-muted)" }}>0{i + 1}</span>
                <Icon size={20} style={{ color: "var(--accent-text)" }} aria-hidden="true" />
              </div>
              <h3 className="font-display font-bold text-2xl mt-6">{label}</h3>
              <p className="mt-2 text-sm" style={{ color: "var(--text-3)" }}>{text}</p>
            </li>
          ))}
        </ol>

        <div className="card mt-10 flex flex-col md:flex-row md:items-center gap-4 justify-between">
          <div>
            <h3 className="section-title">Honest about its limits</h3>
            <p className="mt-1 text-sm max-w-3xl" style={{ color: "var(--text-3)" }}>
              CVE matching is keyword-based (false positives are possible) and exploit maturity is a
              heuristic, not live exploit data. Results are leads to investigate, not confirmed
              vulnerabilities. The README documents every known limitation.
            </p>
          </div>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────────────────────── */}
      <footer style={{ borderTop: "1px solid var(--line)" }}>
        <div className="max-w-6xl mx-auto px-6 py-10 flex flex-col md:flex-row gap-6 md:items-center justify-between">
          <div>
            <Logo size={24} />
            <p className="mt-3 text-xs max-w-md" style={{ color: "var(--text-muted)" }}>
              Academic project (PFA, cybersecurity engineering). Not a hardened product.
              Only scan systems you own or are explicitly authorised to test.
            </p>
          </div>
          <nav className="flex gap-5 text-sm" aria-label="Footer">
            <a href="#features" className="link">Features</a>
            <a href="#how-it-works" className="link">How it works</a>
            <Link to="/login" className="link">Sign in</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
