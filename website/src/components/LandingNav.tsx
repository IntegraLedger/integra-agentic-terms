"use client";

import Link from "next/link";
import { useId, useState } from "react";
import { siteConfig } from "@/lib/site";
import { MarkIcon } from "./MarkIcon";

const LINKS = [
  { href: "/quickstart", label: "Quickstart" },
  { href: "/verify-before-sign", label: "How it works" },
  { href: "/protocols", label: "Protocols" },
  { href: "/mcp", label: "MCP Server" },
] as const;

const EXTERNAL = [
  { href: siteConfig.standard.url, label: "The Standard" },
  { href: siteConfig.githubUrl, label: "GitHub" },
] as const;

export function LandingNav() {
  const [open, setOpen] = useState(false);
  const menuId = useId();

  return (
    <nav aria-label="Primary" className="border-b border-fd-border px-6 py-4">
      <div className="mx-auto flex max-w-6xl items-center justify-between">
        <Link href="/" className="flex items-center gap-2 text-lg font-bold">
          <MarkIcon size={28} className="text-fd-primary" />
          Integra Agentic Terms
        </Link>

        <div className="hidden items-center gap-6 text-base md:flex">
          {LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="hover:text-fd-primary"
            >
              {link.label}
            </Link>
          ))}
          {EXTERNAL.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="hover:text-fd-primary"
              target="_blank"
              rel="noopener noreferrer"
            >
              {link.label}
            </a>
          ))}
        </div>

        <button
          type="button"
          className="flex h-8 w-8 flex-col items-center justify-center gap-1.5 md:hidden"
          onClick={() => setOpen(!open)}
          aria-label="Toggle menu"
          aria-expanded={open}
          aria-controls={menuId}
        >
          <span
            className={`block h-0.5 w-5 bg-fd-foreground transition-transform ${open ? "translate-y-2 rotate-45" : ""}`}
          />
          <span
            className={`block h-0.5 w-5 bg-fd-foreground transition-opacity ${open ? "opacity-0" : ""}`}
          />
          <span
            className={`block h-0.5 w-5 bg-fd-foreground transition-transform ${open ? "-translate-y-2 -rotate-45" : ""}`}
          />
        </button>
      </div>

      <div
        id={menuId}
        hidden={!open}
        className="mt-4 flex flex-col gap-4 text-base md:hidden"
      >
        {LINKS.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="hover:text-fd-primary"
            onClick={() => setOpen(false)}
          >
            {link.label}
          </Link>
        ))}
        {EXTERNAL.map((link) => (
          <a
            key={link.href}
            href={link.href}
            className="hover:text-fd-primary"
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => setOpen(false)}
          >
            {link.label}
          </a>
        ))}
      </div>
    </nav>
  );
}
