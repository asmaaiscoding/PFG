"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { GraphVisualization } from "@/components/GraphVisualization";
import { FindingsPanel } from "@/components/FindingsPanel";
import { ProgressPanel } from "@/components/ProgressPanel";

export interface Finding {
  endpoint_id: string;
  subtype: string;
  severity: string;
  route?: string;
  method?: string;
}

export interface GraphData {
  nodes: Array<{
    id: string;
    type: string;
    route?: string;
    method?: string;
    requires_auth?: boolean;
  }>;
  edges: Array<{
    source: string;
    target: string;
    type: string;
  }>;
}

export interface ProgressUpdate {
  step: string;
  message: string;
  progress: number;
  data?: Record<string, unknown>;
}

type AnalysisState =
  | "idle"
  | "connecting"
  | "building_pfg"
  | "pfg_built"
  | "gnn_inference"
  | "gnn_complete"
  | "done"
  | "error";

export default function AnalyzePage() {
  const params = useParams();
  const appId = params.appId as string;

  const [state, setState] = useState<AnalysisState>("idle");
  const [progress, setProgress] = useState<ProgressUpdate[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const startAnalysis = useCallback(async () => {
    setState("connecting");
    setProgress([]);
    setGraphData(null);
    setFindings([]);
    setError(null);

    try {
      const res = await fetch(`http://localhost:8000/api/analyze/${appId}`, {
        method: "POST",
      });
      const { session_id } = await res.json();

      const ws = new WebSocket(`ws://localhost:8000/ws/analyze/${session_id}`);
      wsRef.current = ws;

      ws.onopen = () => setState("building_pfg");

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        switch (msg.type) {
          case "progress":
            setState(msg.step as AnalysisState);
            setProgress((prev) => [
              ...prev,
              {
                step: msg.step,
                message: msg.message,
                progress: msg.progress,
                data: msg.data,
              },
            ]);
            break;
          case "graph":
            setGraphData({ nodes: msg.nodes, edges: msg.edges });
            break;
          case "results":
            setFindings(msg.findings);
            setSummary(msg.summary);
            setState("done");
            break;
          case "error":
            setError(msg.message);
            setState("error");
            break;
        }
      };

      ws.onerror = () => {
        setError("WebSocket connection failed. Is the backend running?");
        setState("error");
      };

      ws.onclose = () => {
        if (state !== "done" && state !== "error") {
          setState("done");
        }
      };
    } catch {
      setError(
        "Failed to connect to backend. Start it with: python demo/backend/main.py",
      );
      setState("error");
    }
  }, [appId, state]);

  // Auto-start analysis on mount
  useEffect(() => {
    startAnalysis();
    return () => {
      wsRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const latestProgress = progress[progress.length - 1];
  const progressValue = latestProgress?.progress ?? 0;

  return (
    <div className="h-[calc(100vh-65px)] flex flex-col">
      {/* Top bar with app name and progress */}
      <div className="border-b border-white/5 bg-bg-secondary/30 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-white capitalize">
            {appId.replace(/-/g, " ")}
          </h2>
          <StateIndicator state={state} />
        </div>
        <div className="flex items-center gap-4">
          {progressValue > 0 && progressValue < 1 && (
            <div className="w-48 h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-accent to-purple-500 rounded-full transition-all duration-500"
                style={{ width: `${progressValue * 100}%` }}
              />
            </div>
          )}
          {state === "done" && (
            <button
              onClick={startAnalysis}
              className="text-sm px-3 py-1.5 rounded-lg bg-accent/10 text-accent-light border border-accent/20 hover:bg-accent/20 transition-colors">
              Re-analyze
            </button>
          )}
        </div>
      </div>

      {/* Main content area - 3 columns */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Progress log */}
        <div className="w-72 border-r border-white/5 overflow-y-auto">
          <ProgressPanel progress={progress} state={state} error={error} />
        </div>

        {/* Center: Graph visualization */}
        <div className="flex-1 relative">
          {graphData ? (
            <GraphVisualization data={graphData} findings={findings} />
          ) : (
            <div className="absolute inset-0 flex items-center justify-center">
              {state === "error" ? (
                <div className="text-center p-8">
                  <div className="text-red-400 text-lg mb-2">
                    Connection Error
                  </div>
                  <p className="text-slate-400 text-sm max-w-md">{error}</p>
                </div>
              ) : (
                <div className="text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-accent mx-auto mb-4"></div>
                  <p className="text-slate-400">
                    Building Program Flow Graph...
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: Findings panel */}
        <div className="w-80 border-l border-white/5 overflow-y-auto">
          <FindingsPanel findings={findings} summary={summary} state={state} />
        </div>
      </div>
    </div>
  );
}

function StateIndicator({ state }: { state: AnalysisState }) {
  const config: Record<AnalysisState, { color: string; label: string }> = {
    idle: { color: "bg-slate-400", label: "Idle" },
    connecting: { color: "bg-yellow-400 animate-pulse", label: "Connecting" },
    building_pfg: {
      color: "bg-blue-400 animate-pulse",
      label: "Building Graph",
    },
    pfg_built: { color: "bg-blue-400", label: "Graph Ready" },
    gnn_inference: {
      color: "bg-purple-400 animate-pulse",
      label: "GNN Analysis",
    },
    gnn_complete: { color: "bg-green-400", label: "Analysis Complete" },
    done: { color: "bg-green-400", label: "Done" },
    error: { color: "bg-red-400", label: "Error" },
  };

  const { color, label } = config[state];

  return (
    <span className="flex items-center gap-1.5 text-xs text-slate-400">
      <span className={`w-2 h-2 rounded-full ${color}`}></span>
      {label}
    </span>
  );
}
