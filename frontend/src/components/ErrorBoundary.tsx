import { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackText?: string;
  onReset?: () => void;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, info);
  }

  handleReset = () => {
    // Clear corrupted localStorage if it's a state parsing loop
    try {
      localStorage.removeItem("ow_session_id");
      localStorage.removeItem("ow_session_file");
    } catch (e) {
      // ignore
    }
    
    this.setState({ error: null });
    this.props.onReset?.();
    window.location.reload();
  };

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center p-8 rounded-xl h-full w-full min-h-[400px]"
             style={{ background: "#0d0d10", border: "1px solid #2e3038" }}>
          <AlertTriangle style={{ width: 32, height: 32, color: "#ef4444", marginBottom: "12px" }} />
          <span className="text-sm font-mono text-red-500 font-bold mb-3">
            ⚠️ Component Crashed
          </span>
          <p className="text-xs text-slate-500 text-center max-w-md overflow-hidden text-ellipsis mb-6" style={{ wordBreak: "break-all" }}>
            {this.state.error.message || this.props.fallbackText || "An unexpected error occurred."}
          </p>
          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 transition-colors text-xs text-slate-300 border border-slate-700"
          >
            <RotateCcw style={{ width: 14, height: 14 }} />
            Clear State & Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
