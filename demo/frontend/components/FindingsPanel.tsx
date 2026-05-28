"use client";

import type { Finding } from "@/app/analyze/[appId]/page";

interface Props {
  findings: Finding[];
  summary: Record<string, unknown> | null;
  state: string;
}

const SEVERITY_CONFIG: Record<
  string,
  { color: string; bg: string; border: string }
> = {
  CRITICAL: {
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
  },
  HIGH: {
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
  },
  MEDIUM: {
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/20",
  },
  LOW: {
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
  },
};

const SUBTYPE_DESCRIPTIONS: Record<string, string> = {
  MISSING_AUTH: "Endpoint accessible without authentication",
  IDOR: "Insecure Direct Object Reference — user can access other users' resources",
  OBJECT_LEVEL_PERMISSION_BYPASS:
    "Object-level permission checks can be bypassed",
  MISSING_ROLE: "Missing role-based access control check",
  TENANT_ISOLATION_FAILURE: "Cross-tenant data access possible",
  COMBINED: "Multiple authorization weaknesses combined",
};

export function FindingsPanel({ findings, summary, state }: Props) {
  if (state === "idle" || state === "connecting") {
    return (
      <div className="p-4 text-center text-slate-500 mt-12">
        <p className="text-sm">Waiting for analysis...</p>
      </div>
    );
  }

  if (findings.length === 0 && state !== "done") {
    return (
      <div className="p-4">
        <h3 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wider">
          Findings
        </h3>
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <div className="animate-spin rounded-full h-3 w-3 border-b border-accent"></div>
          Running GNN analysis...
        </div>
      </div>
    );
  }

  return (
    <div className="p-4">
      <h3 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wider">
        Findings ({findings.length})
      </h3>

      {/* Summary stats */}
      {summary && (
        <div className="mb-4 p-3 rounded-lg bg-bg-tertiary/50 border border-white/5">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-slate-500">Endpoints</span>
              <span className="block text-white font-medium">
                {(summary.total_endpoints as number)?.toLocaleString()}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Findings</span>
              <span className="block text-red-400 font-medium">
                {summary.total_findings as number}
              </span>
            </div>
          </div>
          {summary.by_subtype ? (
            <div className="mt-2 pt-2 border-t border-white/5 space-y-1">
              {Object.entries(summary.by_subtype as Record<string, number>).map(
                ([subtype, count]) => (
                  <div
                    key={subtype}
                    className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">
                      {subtype.replace(/_/g, " ")}
                    </span>
                    <span className="text-slate-300">{count}</span>
                  </div>
                ),
              )}
            </div>
          ) : null}
        </div>
      )}

      {/* Findings list */}
      <div className="space-y-2">
        {findings.map((finding, i) => (
          <FindingCard key={i} finding={finding} />
        ))}
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const sevConfig = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.MEDIUM;

  return (
    <div
      className={`rounded-lg border ${sevConfig.border} ${sevConfig.bg} p-3`}>
      <div className="flex items-center justify-between mb-1.5">
        <span className={`text-xs font-semibold ${sevConfig.color}`}>
          {finding.severity}
        </span>
        <span className="text-xs text-slate-500 font-mono">
          {finding.method || "GET"}
        </span>
      </div>
      <div className="text-sm text-white font-mono truncate mb-1">
        {finding.route || finding.endpoint_id}
      </div>
      <div className="text-xs text-slate-400">
        {SUBTYPE_DESCRIPTIONS[finding.subtype] ||
          finding.subtype.replace(/_/g, " ")}
      </div>
      <div className="mt-1.5">
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-500">
          {finding.subtype}
        </span>
      </div>
    </div>
  );
}
