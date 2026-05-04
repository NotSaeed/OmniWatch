import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";

interface Command {
  id:      string;
  label:   string;
  hint?:   string;
  action:  () => void;
}

interface CommandPaletteProps {
  open:     boolean;
  onClose:  () => void;
  onFilter: (severity: string) => void;
  onClear:  () => void;
  onExport?: () => void;
}

export function CommandPalette({ open, onClose, onFilter, onClear, onExport }: CommandPaletteProps) {
  const [query,       setQuery]       = useState("");
  const [activeIdx,   setActiveIdx]   = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const baseCommands: Command[] = [
    { id: "critical", label: "Show Critical alerts",  hint: "severity:CRITICAL", action: () => onFilter("CRITICAL") },
    { id: "high",     label: "Show High alerts",      hint: "severity:HIGH",     action: () => onFilter("HIGH") },
    { id: "medium",   label: "Show Medium alerts",    hint: "severity:MEDIUM",   action: () => onFilter("MEDIUM") },
    { id: "low",      label: "Show Low alerts",       hint: "severity:LOW",      action: () => onFilter("LOW") },
    { id: "clear",    label: "Clear all filters",     hint: "reset",             action: () => onClear() },
    ...(onExport ? [{ id: "export", label: "Export to CSV", hint: "download", action: onExport }] : []),
  ];

  const filtered = query.trim()
    ? baseCommands.filter(c =>
        c.label.toLowerCase().includes(query.toLowerCase()) ||
        (c.hint?.toLowerCase().includes(query.toLowerCase()) ?? false)
      )
    : baseCommands;

  // Clamp activeIdx when filtered list changes
  useEffect(() => {
    setActiveIdx(i => Math.min(i, Math.max(0, filtered.length - 1)));
  }, [filtered.length]);

  // Focus input on open; reset query on close
  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIdx(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;

    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (e.key === "ArrowDown" || e.key === "j") {
        e.preventDefault();
        setActiveIdx(i => Math.min(i + 1, filtered.length - 1));
      } else if (e.key === "ArrowUp" || e.key === "k") {
        e.preventDefault();
        setActiveIdx(i => Math.max(i - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const cmd = filtered[activeIdx];
        if (cmd) { cmd.action(); onClose(); }
      }
    }
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [open, filtered, activeIdx, onClose]);

  if (!open) return null;

  return (
    <div className="cmd-palette-backdrop" onClick={onClose}>
      <div className="cmd-palette-box" onClick={e => e.stopPropagation()}>

        {/* Search input */}
        <div
          className="flex items-center gap-3 px-4 py-3 border-b"
          style={{ borderColor: "var(--splunk-border-hi)" }}
        >
          <Search className="w-4 h-4 text-slate-500 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => { setQuery(e.target.value); setActiveIdx(0); }}
            placeholder="Filter commands…"
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
          />
          <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-600 border border-slate-700/50">
            Esc
          </kbd>
        </div>

        {/* Command list */}
        <div className="py-1.5 max-h-72 overflow-y-auto">
          {filtered.length === 0 ? (
            <p className="px-4 py-3 text-xs text-slate-600">No commands match.</p>
          ) : (
            filtered.map((cmd, i) => (
              <button
                key={cmd.id}
                onClick={() => { cmd.action(); onClose(); }}
                onMouseEnter={() => setActiveIdx(i)}
                className="w-full flex items-center justify-between px-4 py-2.5 text-sm transition-colors"
                style={{
                  background: i === activeIdx ? "rgba(6,182,212,0.08)" : "transparent",
                  color: i === activeIdx ? "#e2e8f0" : "#94a3b8",
                }}
              >
                <span className="text-left">{cmd.label}</span>
                {cmd.hint && (
                  <span className="font-mono text-[10px] text-slate-600 ml-4 shrink-0">{cmd.hint}</span>
                )}
              </button>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div
          className="px-4 py-2 border-t flex items-center gap-3 text-[10px] text-slate-700"
          style={{ borderColor: "var(--splunk-border)" }}
        >
          <span><kbd className="font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="font-mono">Enter</kbd> select</span>
          <span><kbd className="font-mono">Esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
