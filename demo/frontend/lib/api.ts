const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function fetchCodebases() {
  const res = await fetch(`${API_BASE}/api/codebases`);
  if (!res.ok) throw new Error("Failed to fetch codebases");
  return res.json();
}

export async function startAnalysis(
  appId: string,
): Promise<{ session_id: string }> {
  const res = await fetch(`${API_BASE}/api/analyze/${appId}`, {
    method: "POST",
  });
  if (!res.ok) throw new Error("Failed to start analysis");
  return res.json();
}

export function createAnalysisSocket(sessionId: string): WebSocket {
  const wsBase = API_BASE.replace("http", "ws");
  return new WebSocket(`${wsBase}/ws/analyze/${sessionId}`);
}
