/**
 * The site mark: a document divided by a stepped cut.
 *
 * The indenture. A deed was written out twice on one sheet and cut apart along a
 * toothed line; each party kept a half, and the teeth had to line up or the
 * document in your hand was a forgery. That is what this package does — the
 * fingerprint the seller advertised against the one recomputed over the bytes
 * actually served — so the mark states the mechanism rather than a posture.
 *
 * The seam deliberately runs edge to edge, from x=6 to x=42, because a cut that
 * stops short of the border is a decoration and a cut that crosses it is a cut.
 *
 * Inline SVG on `currentColor` rather than a pair of theme-swapped image files —
 * the mark has one colour, so a second asset would only be a second thing to
 * keep in sync with the palette. `icon.svg` and `apple-icon.tsx` carry the same
 * geometry filled, because a stroked mark disappears at favicon size.
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
      <rect
        x="6"
        y="6"
        width="36"
        height="36"
        rx="7"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        d="M 6 24 h 9 v -5 h 9 v 10 h 9 v -5 h 9"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
