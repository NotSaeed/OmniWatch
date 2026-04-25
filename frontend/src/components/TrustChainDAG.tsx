/**
 * Sprint 5 — Cryptographic Trust Chain DAG (Three.js / R3F)
 *
 * A 3D Directed Acyclic Graph visualizing the dual-verification pipeline:
 *   Edge Telemetry → STARK Proof → Human FIDO2 Signature → Remediation
 *
 * Graceful degradation: if WebGL fails, renders a 2D CSS-grid fallback.
 */

import { useState, useEffect, useRef, useMemo, Suspense } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Html } from "@react-three/drei";
import * as THREE from "three";

// ── Types ────────────────────────────────────────────────────────────────────

export type NodeState = "pending" | "verifying" | "verified" | "failed";

export interface TrustNode {
  id: string;
  label: string;
  sublabel: string;
  state: NodeState;
  position: [number, number, number];
}

export interface TrustEdge {
  from: string;
  to: string;
}

export interface TrustChainProps {
  nodes?: TrustNode[];
  edges?: TrustEdge[];
  onNodeClick?: (nodeId: string) => void;
  /**
   * When provided, the DAG switches to pipeline mode and renders the
   * telemetry processing chain:
   *   Raw Telemetry → Fixed-Point Scale → zkVM Execution → Hash: [first 8 chars]
   *
   * All four nodes are shown as "verified" and the last node's sublabel is
   * bound to the real SHA-256 chain_tip_hash from the completed session.
   */
  pipelineHash?: string;
}

// ── Default pipeline (zkVM proof flow — used when no pipelineHash is set) ─────

export const DEFAULT_NODES: TrustNode[] = [
  { id: "edge",    label: "Edge Telemetry",    sublabel: "Pi 4 · Zeek + ICSNPP",        state: "verified",  position: [-4, 1.5, 0] },
  { id: "bincode", label: "Bincode Payload",   sublabel: "61-byte serialized struct",    state: "verified",  position: [-1.5, 1.5, 0] },
  { id: "zkvm",    label: "STARK Proof",       sublabel: "RISC Zero zkVM (Machine)",     state: "verifying", position: [1.5, 1.5, 0] },
  { id: "fido2",   label: "FIDO2 Signature",   sublabel: "ECDSA · WebAuthn (Human)",     state: "pending",   position: [1.5, -1, 0] },
  { id: "gate",    label: "Verification Gate", sublabel: "Dual-factor: Machine + Human", state: "pending",   position: [4.5, 0.25, 0] },
  { id: "action",  label: "Remediation",       sublabel: "Network isolation · Firewall", state: "pending",   position: [7, 0.25, 0] },
];

const DEFAULT_EDGES: TrustEdge[] = [
  { from: "edge",    to: "bincode" },
  { from: "bincode", to: "zkvm" },
  { from: "zkvm",    to: "gate" },
  { from: "fido2",   to: "gate" },
  { from: "gate",    to: "action" },
];

// ── Pipeline-mode nodes (shown when pipelineHash is provided) ─────────────────
//
// Visually maps the telemetry ingestion pipeline:
//   Raw Telemetry → Fixed-Point Scaling → zkVM Execution → Hash Committed
//
// All four nodes are derived from the real completed pipeline session.
// The "hash" node sublabel shows the first 8 hex chars of the chain_tip_hash —
// the SHA-256 that binds every alert in the session to its source telemetry.

function buildPipelineNodes(hash: string): TrustNode[] {
  const short = hash.length >= 8 ? hash.substring(0, 8) : hash;
  return [
    {
      id:       "raw",
      label:    "Raw Telemetry",
      sublabel: "Network flows · CSV · Edge capture",
      state:    "verified",
      position: [-4.5, 0, 0],
    },
    {
      id:       "scale",
      label:    "Fixed-Point Scale",
      sublabel: "Python → fp14 · Integer arithmetic",
      state:    "verified",
      position: [-1.5, 0, 0],
    },
    {
      id:       "zkvm_exec",
      label:    "zkVM Execution",
      sublabel: "RISC Zero · 11 rules · No float",
      state:    "verified",
      position: [1.5, 0, 0],
    },
    {
      id:       "hash_commit",
      label:    "Hash Committed",
      sublabel: `SHA-256 · ${short}…`,
      state:    "verified",
      position: [4.5, 0, 0],
    },
  ];
}

const PIPELINE_EDGES: TrustEdge[] = [
  { from: "raw",       to: "scale" },
  { from: "scale",     to: "zkvm_exec" },
  { from: "zkvm_exec", to: "hash_commit" },
];

// ── Color mapping ────────────────────────────────────────────────────────────

const STATE_COLORS: Record<NodeState, string> = {
  pending:   "#4d5060",
  verifying: "#06b6d4",
  verified:  "#22c55e",
  failed:    "#ef4444",
};

// ── Particle Burst ───────────────────────────────────────────────────────────
// Plays a one-shot radial burst when a node transitions to "verified".

const BURST_COUNT = 24;
const BURST_DURATION = 2.2; // seconds

function ParticleBurst({ active, color }: { active: boolean; color: string }) {
  const ref = useRef<THREE.Points>(null!);
  const startRef = useRef<number | null>(null);

  // Evenly-distributed unit-sphere directions (Fibonacci lattice)
  const dirs = useMemo(() => {
    const d = new Float32Array(BURST_COUNT * 3);
    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < BURST_COUNT; i++) {
      const y = 1 - (i / (BURST_COUNT - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const theta = goldenAngle * i;
      d[i * 3]     = r * Math.cos(theta);
      d[i * 3 + 1] = y;
      d[i * 3 + 2] = r * Math.sin(theta);
    }
    return d;
  }, []);

  // Separate mutable position buffer so dirs stays pristine
  const geo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(new Float32Array(BURST_COUNT * 3), 3));
    return g;
  }, []);

  useEffect(() => {
    if (active) startRef.current = null; // reset timer on each activation
  }, [active]);

  useFrame(({ clock }) => {
    if (!ref.current) return;
    const mat = ref.current.material as THREE.PointsMaterial;

    if (!active) {
      mat.opacity = 0;
      return;
    }
    if (startRef.current === null) startRef.current = clock.getElapsedTime();

    const elapsed = clock.getElapsedTime() - startRef.current;
    const t = Math.min(elapsed / BURST_DURATION, 1);
    const radius = t * 1.8;

    const pos = geo.attributes.position.array as Float32Array;
    for (let i = 0; i < BURST_COUNT; i++) {
      pos[i * 3]     = dirs[i * 3]     * radius;
      pos[i * 3 + 1] = dirs[i * 3 + 1] * radius;
      pos[i * 3 + 2] = dirs[i * 3 + 2] * radius;
    }
    geo.attributes.position.needsUpdate = true;

    // Ease-out fade: full opacity until halfway, then fade to 0
    mat.opacity = t < 0.5 ? 1 : Math.max(0, 1 - (t - 0.5) * 2);
    mat.color.set(color);
  });

  return (
    <points ref={ref} geometry={geo}>
      <pointsMaterial size={0.07} color={color} transparent opacity={0} depthWrite={false} />
    </points>
  );
}

// ── 3D Node ──────────────────────────────────────────────────────────────────

function DagNode({ node }: { node: TrustNode }) {
  const meshRef = useRef<THREE.Mesh>(null!);
  const glowRef = useRef<THREE.Mesh>(null!);
  const prevState = useRef<NodeState>(node.state);
  const [burst, setBurst] = useState(false);

  useEffect(() => {
    if (prevState.current !== "verified" && node.state === "verified") {
      setBurst(true);
      const tid = setTimeout(() => setBurst(false), BURST_DURATION * 1000 + 100);
      prevState.current = node.state;
      return () => clearTimeout(tid);
    }
    prevState.current = node.state;
  }, [node.state]);

  const color = useMemo(() => new THREE.Color(STATE_COLORS[node.state]), [node.state]);

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    const yOff = Math.sin(t * 0.8 + node.position[0]) * 0.06;

    if (meshRef.current) {
      meshRef.current.position.y = node.position[1] + yOff;
      if (node.state === "verifying") {
        meshRef.current.scale.setScalar(1 + Math.sin(t * 3) * 0.08);
      }
    }

    if (glowRef.current) {
      glowRef.current.position.y = node.position[1] + yOff;
      const mat = glowRef.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.12 + Math.sin(t * 2) * 0.05;
      glowRef.current.scale.setScalar(1.6 + Math.sin(t * 1.5) * 0.15);
    }
  });

  const stateText =
    node.state === "verified" ? "✓ VERIFIED" :
    node.state === "verifying" ? "⟳ VERIFYING" :
    node.state === "failed" ? "✗ FAILED" : "○ PENDING";

  return (
    <group position={[node.position[0], node.position[1], node.position[2]]}>
      <ParticleBurst active={burst} color={STATE_COLORS[node.state]} />
      {/* Glow */}
      <mesh ref={glowRef}>
        <sphereGeometry args={[0.55, 16, 16]} />
        <meshBasicMaterial color={color} transparent opacity={0.12} depthWrite={false} />
      </mesh>

      {/* Main node */}
      <mesh ref={meshRef}>
        <dodecahedronGeometry args={[0.32, 0]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={
            node.state === "pending"   ? 0.08 :
            node.state === "verifying" ? 0.55 :
            node.state === "verified"  ? 0.80 : 0.50
          }
          metalness={0.85}
          roughness={0.15}
          wireframe={node.state === "pending"}
        />
      </mesh>

      {/* HTML Labels — avoids font loading issues */}
      <Html position={[0, -0.65, 0]} center distanceFactor={8} style={{ pointerEvents: "none" }}>
        <div style={{ textAlign: "center", whiteSpace: "nowrap" }}>
          <div style={{ fontSize: 9, fontFamily: "JetBrains Mono, monospace", color: STATE_COLORS[node.state], marginBottom: 2 }}>
            {stateText}
          </div>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#e4e4e7" }}>
            {node.label}
          </div>
          <div style={{ fontSize: 9, color: "#6b6e80", marginTop: 1 }}>
            {node.sublabel}
          </div>
        </div>
      </Html>
    </group>
  );
}

// ── 3D Edge ──────────────────────────────────────────────────────────────────

function DagEdge({ from, to, verified }: { from: [number, number, number]; to: [number, number, number]; verified: boolean }) {
  const lineObj = useMemo(() => {
    const pts = [
      new THREE.Vector3(...from),
      new THREE.Vector3((from[0] + to[0]) / 2, (from[1] + to[1]) / 2 + 0.25, (from[2] + to[2]) / 2),
      new THREE.Vector3(...to),
    ];
    const curve = new THREE.QuadraticBezierCurve3(pts[0], pts[1], pts[2]);
    const geo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(20));
    const mat = new THREE.LineBasicMaterial({
      color: verified ? "#22c55e" : "#2e3038",
      transparent: true,
      opacity: verified ? 0.7 : 0.3,
    });
    return new THREE.Line(geo, mat);
  }, [from, to, verified]);

  return <primitive object={lineObj} />;
}

// ── Scene ────────────────────────────────────────────────────────────────────

function TrustChainScene({ nodes, edges }: { nodes: TrustNode[]; edges: TrustEdge[] }) {
  const nodeMap = useMemo(() => {
    const m = new Map<string, TrustNode>();
    nodes.forEach(n => m.set(n.id, n));
    return m;
  }, [nodes]);

  return (
    <>
      <ambientLight intensity={0.35} />
      <pointLight position={[5, 5, 5]} intensity={0.8} />
      <pointLight position={[-5, -3, 3]} intensity={0.4} color="#06b6d4" />

      {edges.map(e => {
        const fn = nodeMap.get(e.from);
        const tn = nodeMap.get(e.to);
        if (!fn || !tn) return null;
        return <DagEdge key={`${e.from}-${e.to}`} from={fn.position} to={tn.position} verified={fn.state === "verified" && tn.state === "verified"} />;
      })}

      {nodes.map(n => <DagNode key={n.id} node={n} />)}

      <OrbitControls
        enablePan
        enableZoom
        enableRotate
        maxDistance={18}
        minDistance={4}
        autoRotate
        autoRotateSpeed={0.3}
      />
    </>
  );
}

// ── 2D Fallback ──────────────────────────────────────────────────────────────

function TrustChainFallback2D({ nodes }: { nodes: TrustNode[] }) {
  return (
    <div className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
        <span className="text-[10px] text-amber-500/80">WebGL unavailable — 2D fallback</span>
      </div>
      <div className="grid grid-cols-6 gap-3">
        {nodes.map(node => (
          <div
            key={node.id}
            className="rounded-lg p-3 transition-all"
            style={{
              background: node.state === "verified" ? "rgba(34,197,94,0.08)"
                : node.state === "verifying" ? "rgba(6,182,212,0.08)"
                : node.state === "failed" ? "rgba(239,68,68,0.08)"
                : "rgba(255,255,255,0.03)",
              border: `1px solid ${STATE_COLORS[node.state]}40`,
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full" style={{
                background: STATE_COLORS[node.state],
                boxShadow: node.state !== "pending" ? `0 0 8px ${STATE_COLORS[node.state]}60` : "none",
              }} />
              <span className="text-[9px] font-mono uppercase" style={{ color: STATE_COLORS[node.state] }}>{node.state}</span>
            </div>
            <p className="text-xs font-semibold text-white/90">{node.label}</p>
            <p className="text-[10px] mt-0.5" style={{ color: "#6b6e80" }}>{node.sublabel}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Exported component ───────────────────────────────────────────────────────

export function TrustChainDAG({
  nodes = DEFAULT_NODES,
  edges = DEFAULT_EDGES,
  pipelineHash,
}: TrustChainProps) {
  // When a completed pipeline session hash is available, switch to pipeline
  // mode: override nodes/edges with the real processing chain.
  const activeNodes = pipelineHash ? buildPipelineNodes(pipelineHash) : nodes;
  const activeEdges = pipelineHash ? PIPELINE_EDGES                   : edges;
  const [webglOk, setWebglOk] = useState(true);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl2") || c.getContext("webgl");
      if (!gl) setWebglOk(false);
    } catch { setWebglOk(false); }
  }, []);

  if (!webglOk || errored) {
    return <TrustChainFallback2D nodes={activeNodes} />;
  }

  const subtitle = pipelineHash
    ? `Telemetry pipeline · Hash: ${pipelineHash.substring(0, 16)}… · Drag to rotate`
    : "Spatial DAG · Dual-verification pipeline · Drag to rotate";

  return (
    <div className="relative w-full" style={{ height: 380 }}>
      {/* Title */}
      <div className="absolute top-3 left-4 z-10 pointer-events-none">
        <h3 className="text-xs font-bold text-white/90 tracking-wide">Cryptographic Trust Chain</h3>
        <p className="text-[10px] mt-0.5" style={{ color: "#6b6e80" }}>{subtitle}</p>
      </div>

      {/* Legend */}
      <div className="absolute top-3 right-4 z-10 flex items-center gap-3 pointer-events-none">
        {(["verified", "verifying", "pending", "failed"] as NodeState[]).map(s => (
          <span key={s} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{
              background: STATE_COLORS[s],
              boxShadow: s !== "pending" ? `0 0 6px ${STATE_COLORS[s]}50` : "none",
            }} />
            <span className="text-[9px] font-mono uppercase" style={{ color: STATE_COLORS[s] }}>{s}</span>
          </span>
        ))}
      </div>

      {/* Canvas with bloom-sim filter */}
      <div style={{ position: "absolute", inset: 0, filter: "brightness(1.08) saturate(1.18) contrast(1.04)" }}>
        <Canvas
          camera={{ position: [1.5, 1, 9], fov: 50 }}
          gl={{ antialias: true, alpha: true }}
          style={{ background: "#0a0a0d" }}
          onError={() => setErrored(true)}
        >
          <Suspense fallback={null}>
            <TrustChainScene nodes={activeNodes} edges={activeEdges} />
          </Suspense>
        </Canvas>
      </div>

      {/* HUD grid — ICS command-center aesthetic */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "linear-gradient(rgba(6,182,212,0.025) 1px, transparent 1px)," +
            "linear-gradient(90deg, rgba(6,182,212,0.025) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          zIndex: 2,
        }}
      />

      {/* Scanline overlay */}
      <div
        className="pointer-events-none absolute inset-0 ics-scanlines"
        style={{ zIndex: 3 }}
      />

      {/* Vignette — darken corners like a CRT */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 90% 80% at 50% 50%, transparent 55%, rgba(0,0,0,0.55) 100%)",
          zIndex: 4,
        }}
      />

      {/* Corner brackets — ICS HUD chrome */}
      {(["top-0 left-0", "top-0 right-0", "bottom-0 left-0", "bottom-0 right-0"] as const).map((pos, i) => (
        <div key={i} className={`pointer-events-none absolute ${pos} z-[5] w-5 h-5`}>
          <svg viewBox="0 0 20 20" width="20" height="20">
            <path
              d={i === 0 ? "M0 10 L0 0 L10 0" : i === 1 ? "M20 10 L20 0 L10 0" : i === 2 ? "M0 10 L0 20 L10 20" : "M20 10 L20 20 L10 20"}
              fill="none" stroke="#06b6d430" strokeWidth="1"
            />
          </svg>
        </div>
      ))}

      <div className="absolute bottom-2 left-1/2 -translate-x-1/2 z-10 pointer-events-none">
        <span className="text-[9px] font-mono" style={{ color: "#3d3f4a" }}>
          Drag to rotate · Scroll to zoom
        </span>
      </div>
    </div>
  );
}
