import { ImageResponse } from "next/og";
import { siteConfig } from "@/lib/site";

// Required for the generated image route under `output: export`.
export const dynamic = "force-static";

export const alt = siteConfig.ogImageAlt;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

/**
 * Branded 1200×630 social share card. Statically rendered at build time, so it
 * works under `output: export`. Uses the embedded default font (no network
 * fetch) to keep the static build hermetic.
 */
export default function OpenGraphImage() {
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        padding: "72px 80px",
        background:
          "linear-gradient(135deg, #0b1220 0%, #0f1a30 55%, #0b1220 100%)",
        color: "#e7edf5",
        fontFamily: "sans-serif",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          letterSpacing: 4,
          fontSize: 24,
          fontWeight: 600,
          color: "#8aa0bd",
        }}
      >
        APACHE 2.0 · NO ACCOUNT · NO KEY · NO TELEMETRY
      </div>

      <div style={{ display: "flex", flexDirection: "column" }}>
        <div
          style={{
            fontSize: 92,
            fontWeight: 800,
            lineHeight: 1.02,
            letterSpacing: -2,
          }}
        >
          Integra Agentic Terms
        </div>
        <div
          style={{
            marginTop: 20,
            fontSize: 40,
            fontWeight: 600,
            color: "#4a9eed",
          }}
        >
          Verify before sign, as a runtime guarantee
        </div>
        <div
          style={{
            marginTop: 36,
            display: "flex",
            alignSelf: "flex-start",
            padding: "14px 26px",
            borderRadius: 12,
            border: "1px solid rgba(43,194,151,0.4)",
            background: "rgba(43,194,151,0.08)",
            fontSize: 30,
            color: "#2bc297",
          }}
        >
          npm install {siteConfig.packages.guard.name}
        </div>
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: 26,
          color: "#8aa0bd",
        }}
      >
        <span style={{ color: "#e7edf5", fontWeight: 600 }}>
          {siteConfig.url.replace("https://", "")}
        </span>
        <span>Works against any seller</span>
      </div>
    </div>,
    size,
  );
}
