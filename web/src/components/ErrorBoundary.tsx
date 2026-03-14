import React from "react";

type Props = {
  children: React.ReactNode;
};

type State = {
  hasError: boolean;
  errorMessage: string;
  stack?: string;
};

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, errorMessage: "" };
  }

  static getDerivedStateFromError(err: any): State {
    const msg = String(err?.message || err || "Unknown UI error");
    const stack = String(err?.stack || "");
    return { hasError: true, errorMessage: msg, stack };
  }

  componentDidCatch(err: any) {
    // Keep console error (useful in prod logs). Avoid spamming if you later add telemetry.
    // eslint-disable-next-line no-console
    console.error("UI ErrorBoundary caught:", err);
  }

  private reset = () => {
    // Hard reset UI state.
    this.setState({ hasError: false, errorMessage: "", stack: "" });
  };

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div style={{ maxWidth: 900, margin: "0 auto", padding: 16 }}>
        <h2 style={{ marginTop: 0 }}>Something went wrong</h2>
        <div style={{ background: "#fff", border: "1px solid #ddd", borderRadius: 12, padding: 14 }}>
          <div style={{ fontWeight: 800, color: "#a00" }}>{this.state.errorMessage}</div>
          {this.state.stack ? (
            <pre style={{ marginTop: 10, whiteSpace: "pre-wrap", opacity: 0.8 }}>
              {this.state.stack.slice(0, 5000)}
            </pre>
          ) : null}
          <div style={{ marginTop: 12, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button onClick={this.reset}>Try again</button>
            <button onClick={() => window.location.reload()}>Reload</button>
          </div>
        </div>

        <div style={{ marginTop: 12, fontSize: 13, opacity: 0.75 }}>
          If this persists, switch nodes (top-left pill) or refresh.
        </div>
      </div>
    );
  }
}

