"use client";

import { useEffect, useRef, useMemo } from "react";
import type { GraphData, Finding } from "@/app/analyze/[appId]/page";

interface Props {
  data: GraphData;
  findings: Finding[];
}

// Node type -> color mapping
const NODE_COLORS: Record<string, string> = {
  ENDPOINT: "#6366f1",
  VIEW: "#8b5cf6",
  DATA_ACCESS: "#ec4899",
  MODEL: "#f59e0b",
  PERMISSION: "#10b981",
  MIDDLEWARE: "#06b6d4",
  SERIALIZER: "#14b8a6",
};

export function GraphVisualization({ data, findings }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animFrameRef = useRef<number>(0);

  // Build set of vulnerable endpoint IDs for highlighting
  const vulnerableIds = useMemo(
    () => new Set(findings.map((f) => f.endpoint_id)),
    [findings],
  );

  // Simple force-directed layout
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d")!;
    if (!ctx) return;

    // Resize canvas
    const rect = container.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    const W = rect.width;
    const H = rect.height;

    // Subsample nodes for large graphs (>500 nodes)
    const MAX_DISPLAY = 300;
    let displayNodes = data.nodes;
    let displayEdges = data.edges;

    if (data.nodes.length > MAX_DISPLAY) {
      // Prioritize vulnerable endpoints and their connected nodes
      const priorityIds = new Set<string>();
      vulnerableIds.forEach((id) => priorityIds.add(id));

      // Add endpoints first
      const endpoints = data.nodes.filter((n) => n.type === "ENDPOINT");
      endpoints.forEach((n) => priorityIds.add(n.id));

      // Sample remaining
      const remaining = data.nodes.filter((n) => !priorityIds.has(n.id));
      const sampled = remaining.slice(0, MAX_DISPLAY - priorityIds.size);

      const allIds = new Set([...priorityIds, ...sampled.map((n) => n.id)]);
      displayNodes = data.nodes.filter((n) => allIds.has(n.id));
      displayEdges = data.edges.filter(
        (e) => allIds.has(e.source) && allIds.has(e.target),
      );
    }

    // Initialize positions
    type NodePos = {
      x: number;
      y: number;
      vx: number;
      vy: number;
      id: string;
      type: string;
    };
    const positions: NodePos[] = displayNodes.map((n) => ({
      x: W / 2 + (Math.random() - 0.5) * W * 0.8,
      y: H / 2 + (Math.random() - 0.5) * H * 0.8,
      vx: 0,
      vy: 0,
      id: n.id,
      type: n.type,
    }));

    const posMap = new Map(positions.map((p, i) => [p.id, i]));

    // Simple force simulation (limited iterations)
    let iteration = 0;
    const MAX_ITER = 150;

    function simulate() {
      if (iteration >= MAX_ITER) return;

      const alpha = 1 - iteration / MAX_ITER;

      // Repulsion
      for (let i = 0; i < positions.length; i++) {
        for (let j = i + 1; j < positions.length; j++) {
          const dx = positions[j].x - positions[i].x;
          const dy = positions[j].y - positions[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = (alpha * 500) / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          positions[i].vx -= fx;
          positions[i].vy -= fy;
          positions[j].vx += fx;
          positions[j].vy += fy;
        }
      }

      // Attraction (edges)
      for (const edge of displayEdges) {
        const si = posMap.get(edge.source);
        const ti = posMap.get(edge.target);
        if (si === undefined || ti === undefined) continue;
        const dx = positions[ti].x - positions[si].x;
        const dy = positions[ti].y - positions[si].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = alpha * dist * 0.01;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        positions[si].vx += fx;
        positions[si].vy += fy;
        positions[ti].vx -= fx;
        positions[ti].vy -= fy;
      }

      // Center gravity
      for (const p of positions) {
        p.vx += (W / 2 - p.x) * 0.001 * alpha;
        p.vy += (H / 2 - p.y) * 0.001 * alpha;
      }

      // Update positions
      for (const p of positions) {
        p.vx *= 0.6;
        p.vy *= 0.6;
        p.x += p.vx;
        p.y += p.vy;
        // Keep in bounds
        p.x = Math.max(20, Math.min(W - 20, p.x));
        p.y = Math.max(20, Math.min(H - 20, p.y));
      }

      iteration++;
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);

      // Draw edges
      ctx.strokeStyle = "rgba(99, 102, 241, 0.1)";
      ctx.lineWidth = 0.5;
      for (const edge of displayEdges) {
        const si = posMap.get(edge.source);
        const ti = posMap.get(edge.target);
        if (si === undefined || ti === undefined) continue;
        ctx.beginPath();
        ctx.moveTo(positions[si].x, positions[si].y);
        ctx.lineTo(positions[ti].x, positions[ti].y);
        ctx.stroke();
      }

      // Draw nodes
      for (const p of positions) {
        const isVulnerable = vulnerableIds.has(p.id);
        const color = NODE_COLORS[p.type] || "#64748b";
        const radius = isVulnerable ? 6 : 3;

        if (isVulnerable) {
          // Glow effect for vulnerable nodes
          ctx.beginPath();
          ctx.arc(p.x, p.y, radius + 4, 0, Math.PI * 2);
          ctx.fillStyle = "rgba(239, 68, 68, 0.3)";
          ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = isVulnerable ? "#ef4444" : color;
        ctx.fill();
      }

      // Legend
      ctx.font = "11px system-ui";
      let ly = 20;
      ctx.fillStyle = "rgba(226, 232, 240, 0.7)";
      ctx.fillText(
        `${data.nodes.length} nodes · ${data.edges.length} edges`,
        12,
        ly,
      );
      ly += 18;
      if (displayNodes.length < data.nodes.length) {
        ctx.fillStyle = "rgba(148, 163, 184, 0.5)";
        ctx.fillText(
          `(showing ${displayNodes.length} of ${data.nodes.length})`,
          12,
          ly,
        );
      }
    }

    function animate() {
      simulate();
      draw();
      if (iteration < MAX_ITER) {
        animFrameRef.current = requestAnimationFrame(animate);
      } else {
        draw(); // Final draw
      }
    }

    animate();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
    };
  }, [data, findings, vulnerableIds]);

  return (
    <div ref={containerRef} className="absolute inset-0 bg-bg-primary">
      <canvas ref={canvasRef} className="w-full h-full" />
      {/* Node type legend */}
      <div className="absolute bottom-4 left-4 bg-bg-secondary/90 backdrop-blur-sm rounded-lg p-3 border border-white/5">
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs text-slate-400">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span>{type.toLowerCase().replace("_", " ")}</span>
            </div>
          ))}
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <span className="text-red-400">vulnerable</span>
          </div>
        </div>
      </div>
    </div>
  );
}
