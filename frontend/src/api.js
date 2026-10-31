const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.PROD ? "/api" : "http://127.0.0.1:8000");

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.detail || `Request failed with status ${response.status}`);
  }
  return body;
}

export const api = {
  baseUrl: API_BASE,
  health: () => request("/health"),
  modelStatus: () => request("/model/status"),
  routes: () => request("/routes"),
  history: () => request("/history?limit=100"),
  detect: (event) =>
    request("/detect", {
      method: "POST",
      body: JSON.stringify(event),
    }),
};
