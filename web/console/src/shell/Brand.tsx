export function Brand({ collapsed }: { collapsed?: boolean }) {
  return (
    <div className="xs-brand">
      <span className="xs-brand-mark" aria-hidden="true">
        X
      </span>
      {!collapsed && <span className="xs-brand-name">Xshield</span>}
    </div>
  );
}
