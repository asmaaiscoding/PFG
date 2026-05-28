"use client";

import Link from "next/link";

interface CodebaseCardProps {
  codebase: {
    id: string;
    name: string;
    cves: string[];
    framework: string;
  };
}

const STATS: Record<string, { endpoints: number; description: string }> = {
  "django-mdeditor": {
    endpoints: 5,
    description: "Markdown editor plugin with file upload vulnerabilities",
  },
  nautobot: {
    endpoints: 1716,
    description: "Network automation platform with complex RBAC",
  },
  wger: {
    endpoints: 1088,
    description: "Fitness tracker with user data isolation issues",
  },
  sentry: {
    endpoints: 273,
    description: "Error monitoring platform with org-level access control",
  },
  weblate: {
    endpoints: 450,
    description: "Translation platform with project-level permissions",
  },
  pretix: {
    endpoints: 620,
    description: "Event ticketing system with organizer isolation",
  },
};

export function CodebaseCard({ codebase }: CodebaseCardProps) {
  const stats = STATS[codebase.id] || {
    endpoints: 0,
    description: "Django application",
  };

  return (
    <Link href={`/analyze/${codebase.id}`}>
      <div className="group relative overflow-hidden rounded-xl border border-white/5 bg-bg-secondary hover:border-accent/30 transition-all duration-300 hover:shadow-lg hover:shadow-accent/5 p-6 cursor-pointer">
        {/* Gradient overlay on hover */}
        <div className="absolute inset-0 bg-gradient-to-br from-accent/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

        <div className="relative">
          {/* Framework badge */}
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-accent/10 text-accent-light border border-accent/20">
              {codebase.framework}
            </span>
            <span className="text-xs text-slate-500">
              {stats.endpoints.toLocaleString()} endpoints
            </span>
          </div>

          {/* App name */}
          <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-accent-light transition-colors">
            {codebase.name}
          </h3>

          {/* Description */}
          <p className="text-sm text-slate-400 mb-4 line-clamp-2">
            {stats.description}
          </p>

          {/* CVEs */}
          <div className="flex flex-wrap gap-1.5">
            {codebase.cves.slice(0, 3).map((cve) => (
              <span
                key={cve}
                className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                {cve}
              </span>
            ))}
            {codebase.cves.length > 3 && (
              <span className="text-xs px-2 py-0.5 rounded bg-slate-500/10 text-slate-400">
                +{codebase.cves.length - 3} more
              </span>
            )}
          </div>

          {/* Analyze button */}
          <div className="mt-5 flex items-center text-sm text-accent-light opacity-0 group-hover:opacity-100 transition-opacity">
            <span>Analyze</span>
            <svg
              className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 7l5 5m0 0l-5 5m5-5H6"
              />
            </svg>
          </div>
        </div>
      </div>
    </Link>
  );
}
