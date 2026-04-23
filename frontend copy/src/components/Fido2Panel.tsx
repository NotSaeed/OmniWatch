/**
 * Sprint 3 — FIDO2 Hardware Key Registration & Signing Ceremony UI
 *
 * Provides the analyst-facing buttons to:
 *   1. Register a new hardware key (navigator.credentials.create)
 *   2. View registered credentials
 *
 * The signing ceremony (navigator.credentials.get) is triggered from
 * the verification gate, not from this panel.
 */

import { useState, useCallback } from "react";
import axios from "axios";
import { KeyRound, Plus, CheckCircle2, XCircle, Loader2, ShieldCheck } from "lucide-react";

const http = axios.create({ baseURL: "/api" });

interface Credential {
  credential_id: string;
  user_name: string;
  sign_count: number;
  registered_at: string;
}

/**
 * Decode a base64url string to a Uint8Array (for WebAuthn APIs).
 */
function base64urlToBuffer(b64url: string): ArrayBuffer {
  // Add padding
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

/**
 * Encode an ArrayBuffer to base64url string (for sending back to server).
 */
function bufferToBase64url(buf: ArrayBuffer): string {
  const arr = new Uint8Array(buf);
  let binary = "";
  for (const b of arr) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function Fido2Panel() {
  const [userId]   = useState("analyst-01");
  const [userName] = useState("Security Analyst");
  const [status, setStatus]       = useState<"idle" | "registering" | "success" | "error">("idle");
  const [message, setMessage]     = useState("");
  const [credentials, setCreds]   = useState<Credential[]>([]);
  const [loadingCreds, setLoading] = useState(false);
  const [useMock, setUseMock]     = useState(true); // Default to mock for demo

  // ── Load credentials ──────────────────────────────────────────────────
  const loadCredentials = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await http.get(`/auth/credentials/${userId}`);
      setCreds(resp.data.credentials || []);
    } catch {
      setCreds([]);
    }
    setLoading(false);
  }, [userId]);

  // ── Registration ceremony ───────────────────────────────────────────────
  const registerKey = useCallback(async () => {
    setStatus("registering");
    setMessage("Starting registration ceremony…");

    try {
      // Step 1: Begin registration — get PublicKeyCredentialCreationOptions
      const beginResp = await http.post("/auth/register/begin", {
        user_id: userId,
        user_name: userName,
      });
      const { session_id, options } = beginResp.data;

      // Step 2: Convert base64url fields to ArrayBuffers for WebAuthn API
      const publicKey = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        user: {
          ...options.user,
          id: base64urlToBuffer(options.user.id),
        },
        excludeCredentials: (options.excludeCredentials || []).map((c: any) => ({
          ...c,
          id: base64urlToBuffer(c.id),
        })),
      };

      let credentialData;

      if (useMock) {
        setMessage("Generating Software Mock (ECDSA keypair)…");
        // Wait 1.5s for "hardware tap" effect
        await new Promise(r => setTimeout(r, 1500));
        
        credentialData = {
          id: "mock-cred-id-1234",
          rawId: "bW9jay1jcmVkLWlkLTEyMzQ", // base64url "mock-cred-id-1234"
          type: "public-key",
          mock_fido2: true, // Special flag for backend bypass
        };
      } else {
        setMessage("Touch your hardware key to register…");

        // Step 3: Call navigator.credentials.create()
        const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential;

        if (!credential) {
          throw new Error("No credential returned from authenticator");
        }

        // Step 4: Serialize response for the server
        const response = credential.response as AuthenticatorAttestationResponse;
        credentialData = {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: credential.type,
          response: {
            attestationObject: bufferToBase64url(response.attestationObject),
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
          },
        };
      }

      // Step 5: Complete registration on the server
      await http.post("/auth/register/complete", {
        session_id,
        credential: credentialData,
      });

      setStatus("success");
      setMessage("Hardware key registered successfully!");
      loadCredentials();
    } catch (err: any) {
      setStatus("error");
      const msg = err?.response?.data?.detail || err?.message || "Registration failed";
      setMessage(msg);
    }
  }, [userId, userName, loadCredentials]);

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ background: "#0d0d10", border: "1px solid #1a1a1f" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: "1px solid #1a1a1f" }}
      >
        <div className="flex items-center gap-2.5">
          <ShieldCheck style={{ width: 14, height: 14, color: "#d946ef" }} />
          <span className="text-xs font-bold text-white/90 tracking-wide">
            FIDO2 Hardware Key
          </span>
          <span className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
            WebAuthn · Proof of Oversight
          </span>
        </div>
        <button
          onClick={loadCredentials}
          className="text-[10px] px-2 py-1 rounded transition-colors hover:bg-white/5"
          style={{ color: "#6b6e80" }}
        >
          {loadingCreds ? "Loading…" : "Refresh"}
        </button>
      </div>

      {/* Content */}
      <div className="p-4 space-y-4">
        {/* Registration button */}
        <div className="flex items-center gap-3">
          <button
            onClick={registerKey}
            disabled={status === "registering"}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold
                       transition-all active:scale-95 disabled:opacity-50 disabled:cursor-wait"
            style={{
              background: "linear-gradient(135deg, rgba(217,70,239,0.15), rgba(6,182,212,0.15))",
              border: "1px solid rgba(217,70,239,0.30)",
              color: "#e0aaff",
            }}
          >
            {status === "registering" ? (
              <Loader2 style={{ width: 13, height: 13 }} className="animate-spin" />
            ) : (
              <Plus style={{ width: 13, height: 13 }} />
            )}
            {status === "registering" ? "Waiting for Key…" : "Register Hardware Key"}
          </button>

          {/* Status message */}
          {message && (
            <div className="flex items-center gap-1.5 text-[10px]">
              {status === "success" && <CheckCircle2 style={{ width: 12, height: 12, color: "#22c55e" }} />}
              {status === "error"   && <XCircle style={{ width: 12, height: 12, color: "#ef4444" }} />}
              {status === "registering" && <Loader2 style={{ width: 12, height: 12, color: "#06b6d4" }} className="animate-spin" />}
              <span style={{ color: status === "success" ? "#22c55e" : status === "error" ? "#ef4444" : "#06b6d4" }}>
                {message}
              </span>
            </div>
          )}

          {/* Mock Checkbox */}
          <label className="flex items-center gap-2 cursor-pointer ml-4">
            <input 
              type="checkbox" 
              checked={useMock} 
              onChange={e => setUseMock(e.target.checked)}
              disabled={status === "registering"}
              className="rounded bg-black border-[#1a1a1f] text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0"
            />
            <span className="text-[10px] text-gray-400 select-none">Use Software Mock (Demo)</span>
          </label>
        </div>

        {/* Credential list */}
        {credentials.length > 0 && (
          <div>
            <p className="text-[9px] uppercase tracking-widest font-semibold mb-2" style={{ color: "#4d5060" }}>
              Enrolled Keys
            </p>
            <div className="space-y-1.5">
              {credentials.map(cred => (
                <div
                  key={cred.credential_id}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg"
                  style={{ background: "rgba(255,255,255,0.02)", border: "1px solid #1a1a1f" }}
                >
                  <KeyRound style={{ width: 12, height: 12, color: "#d946ef" }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-medium text-white/80 truncate">{cred.user_name}</p>
                    <p className="text-[9px] font-mono truncate" style={{ color: "#4d5060" }}>
                      {cred.credential_id.slice(0, 24)}…
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-[10px] font-mono" style={{ color: "#6b6e80" }}>
                      {cred.sign_count} signs
                    </p>
                    <p className="text-[9px]" style={{ color: "#3d3f4a" }}>
                      {new Date(cred.registered_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {credentials.length === 0 && !loadingCreds && (
          <p className="text-[10px]" style={{ color: "#3d3f4a" }}>
            No hardware keys enrolled. Click "Register Hardware Key" and touch your FIDO2 authenticator.
          </p>
        )}
      </div>
    </div>
  );
}
