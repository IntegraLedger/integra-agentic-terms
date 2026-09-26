import Link from "next/link";

export default function NotFound() {
  return (
    <main id="main" className="mx-auto flex min-h-[60vh] max-w-xl flex-col items-center justify-center gap-4 px-6 text-center">
      <h1 className="text-3xl font-semibold">Page not found</h1>
      <p className="text-fd-muted-foreground">No page lives at this address.</p>
      <Link href="/" className="text-fd-primary hover:underline">
        Go to the introduction
      </Link>
    </main>
  );
}
