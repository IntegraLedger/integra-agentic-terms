import { ImageResponse } from "next/og";

// Required for the generated image route under `output: export`.
export const dynamic = "force-static";

export const size = { width: 180, height: 180 };
export const contentType = "image/png";

/**
 * iOS home-screen icon. iOS ignores SVG here, so the mark is rasterized at build time
 * from the same geometry as `icon.svg` — one drawing, two formats.
 */
export default function AppleIcon() {
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#0b1220",
      }}
    >
      <svg
        width="132"
        height="132"
        viewBox="0 0 48 48"
        role="img"
        aria-label="Integra Agentic Terms"
      >
        <path
          d="M 24 3 L 42 9.5 V 23.7 C 42 34.7 34.7 42.7 24 46 C 13.3 42.7 6 34.7 6 23.7 V 9.5 Z"
          fill="#2563d9"
        />
        <path
          d="M 14.5 22.5 h 19 M 19.5 15.5 v 7 M 28.5 15.5 v 7 M 24 26.5 v 6"
          fill="none"
          stroke="#ffffff"
          strokeWidth="3.5"
          strokeLinecap="round"
        />
      </svg>
    </div>,
    size,
  );
}
