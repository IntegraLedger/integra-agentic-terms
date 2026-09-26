"use client";

import { useEffect, useId, useState } from "react";

/** A Mermaid diagram, rendered in the browser in the page's light or dark theme. */
export function Mermaid({ chart }: { chart: string }) {
  const id = useId().replace(/[^a-zA-Z0-9]/g, "");
  const [svg, setSvg] = useState<string>("");
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    const read = () => setDark(root.classList.contains("dark"));
    read();
    const observer = new MutationObserver(read);
    observer.observe(root, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let live = true;
    void import("mermaid").then(async ({ default: mermaid }) => {
      mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: dark ? "dark" : "default" });
      const { svg: rendered } = await mermaid.render(`mermaid-${id}-${dark ? "d" : "l"}`, chart);
      if (live) setSvg(rendered);
    });
    return () => {
      live = false;
    };
  }, [chart, dark, id]);

  return svg === "" ? (
    <pre className="mermaid-diagram">{chart}</pre>
  ) : (
    <div className="mermaid-diagram my-6" dangerouslySetInnerHTML={{ __html: svg }} />
  );
}
