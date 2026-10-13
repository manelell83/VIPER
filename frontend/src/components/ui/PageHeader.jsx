/**
 * Consistent page header: eyebrow label, display title, subtitle and an
 * optional actions area on the right (scan selector, buttons...).
 */
export default function PageHeader({ eyebrow, title, subtitle, icon: Icon, children }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4 pb-2">
      <div className="min-w-0">
        {eyebrow && <p className="eyebrow mb-2">{eyebrow}</p>}
        <h1 className="page-title flex items-center gap-3">
          {Icon && <Icon size={24} className="text-accent-text flex-shrink-0" aria-hidden="true" />}
          {title}
        </h1>
        {subtitle && <p className="page-subtitle max-w-2xl">{subtitle}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}
