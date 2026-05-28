import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PFG — Authorization Vulnerability Detector",
  description:
    "Real-time GNN-based vulnerability detection for Django applications",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg-primary antialiased">
        <nav className="border-b border-white/5 bg-bg-secondary/50 backdrop-blur-sm sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent to-purple-500 flex items-center justify-center">
                <span className="text-white font-bold text-sm">P</span>
              </div>
              <h1 className="text-lg font-semibold text-white">
                PFG{" "}
                <span className="text-accent-light font-normal text-sm ml-1">
                  Vulnerability Detector
                </span>
              </h1>
            </div>
            <div className="flex items-center gap-4 text-sm text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                GNN Model Active
              </span>
            </div>
          </div>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
