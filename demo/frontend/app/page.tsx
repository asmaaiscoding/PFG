"use client";

import { useEffect, useState } from "react";
import { CodebaseCard } from "@/components/CodebaseCard";

interface Codebase {
  id: string;
  name: string;
  cves: string[];
  framework: string;
}

export default function HomePage() {
  const [codebases, setCodebases] = useState<Codebase[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:8000/api/codebases")
      .then((res) => res.json())
      .then((data) => {
        setCodebases(data);
        setLoading(false);
      })
      .catch(() => {
        // Fallback demo data if backend not running
        setCodebases([
          {
            id: "django-mdeditor",
            name: "Django Mdeditor",
            cves: ["CVE-2025-13030"],
            framework: "django",
          },
          {
            id: "nautobot",
            name: "Nautobot",
            cves: ["CVE-2023-50263", "CVE-2024-36112"],
            framework: "django",
          },
          {
            id: "wger",
            name: "Wger",
            cves: ["CVE-2026-27839", "CVE-2026-43948"],
            framework: "django",
          },
          {
            id: "sentry",
            name: "Sentry",
            cves: ["CVE-2023-36826", "CVE-2024-45605"],
            framework: "django",
          },
          {
            id: "weblate",
            name: "Weblate",
            cves: ["CVE-2025-67715"],
            framework: "django",
          },
          {
            id: "pretix",
            name: "Pretix",
            cves: ["CVE-2025-14881"],
            framework: "django",
          },
        ]);
        setLoading(false);
      });
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-6 py-12">
      {/* Hero section */}
      <div className="text-center mb-16">
        <h2 className="text-4xl font-bold text-white mb-4">
          Detect Authorization Vulnerabilities
          <br />
          <span className="text-accent-light">Before They Ship</span>
        </h2>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          GNN-powered analysis of Django applications. Select a codebase to see
          real-time graph construction and vulnerability detection.
        </p>
        <div className="flex items-center justify-center gap-6 mt-8 text-sm">
          <div className="flex items-center gap-2 text-slate-300">
            <div className="w-3 h-3 rounded-full bg-accent"></div>
            Program Flow Graph
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <div className="w-3 h-3 rounded-full bg-purple-500"></div>
            GNN Inference
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            Structural Validation
          </div>
        </div>
      </div>

      {/* Codebase grid */}
      {loading ? (
        <div className="flex justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {codebases.map((cb) => (
            <CodebaseCard key={cb.id} codebase={cb} />
          ))}
        </div>
      )}
    </div>
  );
}
