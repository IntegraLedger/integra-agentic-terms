/**
 * The site mark. The artwork is a shield with a gate across it — drawn for the
 * package's former name and NOT redrawn for this one. A shield says "guard",
 * which is the association the rename exists to leave behind, so this glyph is
 * inherited, not chosen. Replacing it is open work.
 *
 * Inline SVG on `currentColor` rather than a pair of theme-swapped image files —
 * the mark has one colour, so a second asset would only be a second thing to
 * keep in sync with the palette.
 */
export function MarkIcon({
  size = 28,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      role="img"
      aria-label="Integra Agentic Terms"
      className={className}
    >
      <path
        d="M 24 4.5 L 40.5 10.5 V 23.7 C 40.5 33.9 33.8 41.3 24 44.5 C 14.2 41.3 7.5 33.9 7.5 23.7 V 10.5 Z"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      {/* The gate: the bar the transaction has to clear before a key is reachable. */}
      <path
        d="M 14.5 22.5 h 19"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <path
        d="M 19.5 15.5 v 7 M 28.5 15.5 v 7 M 24 26.5 v 6"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}
