"use client";

import type { ProgressUpdate } from "@/app/analyze/[appId]/page";

interface Props {
  progress: ProgressUpdate[];
  state: string;
  error: string | null;
}

const STEP_ICONS: Record<string, string> = {
  building_pfg: "🔨",
  pfg_built: "✅",
  gnn_inference: "🧠",
  gnn_complete: "✅",
};

export function ProgressPanel({ progress, state, error }: Props) {
  return (
    <div className="p-4">
      <h3 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wider">
        Analysis Progress
      </h3>

      {/* Pipeline steps */}
      <div className="space-y-1 mb-4">
        <PipelineStep
          label="Build PFG"
          active={state === "building_pfg"}
          done={["pfg_built", "gnn_inference", "gnn_complete", "done"].includes(
            state,
          )}
        />
        <PipelineStep
          label="GNN Inference"
          active={state === "gnn_inference"}
          done={["gnn_complete", "done"].includes(state)}
        />
        <PipelineStep
          label="Structural Validation"
          active={state === "gnn_complete"}
          done={state === "done"}
        />
      </div>

      {/* Progress log */}
      <div className="space-y-2">
        {progress.map((p, i) => (
          <div key={i} className="text-xs">
            <div className="flex items-start gap-2">
              <span>{STEP_ICONS[p.step] || "⏳"}</span>
              <span className="text-slate-300">{p.message}</span>
            </div>
            {p.data ? (
              <div className="ml-6 mt-1 text-slate-500">
                {p.data.nodes_by_type ? (
                  <div className="space-y-0.5">
                    {Object.entries(
                      p.data.nodes_by_type as Record<string, number>,
                    ).map(([type, count]) => (
                      <div key={type} className="flex justify-between">
                        <span>{type.toLowerCase()}</span>
                        <span className="text-slate-400">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400">
          {error}
        </div>
      )}
    </div>
  );
}

function PipelineStep({
  label,
  active,
  done,
}: {
  label: string;
  active: boolean;
  done: boolean;
}) {
  return (
    <div className="flex items-center gap-2 text-xs py-1.5 px-2 rounded">
      {done ? (
        <svg
          className="w-4 h-4 text-green-400"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M5 13l4 4L19 7"
          />
        </svg>
      ) : active ? (
        <div className="w-4 h-4 flex items-center justify-center">
          <div className="w-2.5 h-2.5 rounded-full bg-accent animate-pulse"></div>
        </div>
      ) : (
        <div className="w-4 h-4 flex items-center justify-center">
          <div className="w-2 h-2 rounded-full bg-slate-600"></div>
        </div>
      )}
      <span
        className={`${done ? "text-green-400" : active ? "text-white" : "text-slate-500"}`}>
        {label}
      </span>
    </div>
  );
}
