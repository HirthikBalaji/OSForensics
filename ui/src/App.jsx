import React, { useState } from "react";

export default function App() {
  const [path, setPath] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image_path: path }),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const json = await res.json();
      setResult(json);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  async function upload(e) {
    e.preventDefault();
    if (!file) return setError("No file selected");
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file, file.name);
      const res = await fetch("http://127.0.0.1:8000/upload", {
        method: "POST",
        body: fd,
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const json = await res.json();
      setResult(json);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header>
        <h1>OS Forensics — UI</h1>
      </header>

      <main>
        <form onSubmit={submit} style={{ marginBottom: 16 }}>
          <label style={{ display: "block", marginBottom: 8 }}>
            Path to image or mount point
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/full/path/to/test.img or /mnt/snapshot"
              style={{ width: "100%", padding: 8, marginTop: 6 }}
            />
          </label>
          <button type="submit" disabled={loading || !path}>
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </form>

        <form onSubmit={upload} style={{ marginBottom: 24 }}>
          <label style={{ display: "block", marginBottom: 8 }}>
            Or upload an image file
            <input
              type="file"
              accept="*"
              onChange={(e) => setFile(e.target.files[0])}
              style={{ display: "block", marginTop: 6 }}
            />
          </label>
          <button type="submit" disabled={loading || !file}>
            {loading ? "Uploading..." : "Upload & Analyze"}
          </button>
        </form>

        {error && (
          <div style={{ color: "#b00020", marginBottom: 8 }}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <section>
            <h2>Report</h2>
            <pre style={{ whiteSpace: "pre-wrap", background: "#f4f6f8", padding: 12, borderRadius: 6 }}>
              {JSON.stringify(result, null, 2)}
            </pre>
          </section>
        )}
      </main>
    </div>
  );
}
