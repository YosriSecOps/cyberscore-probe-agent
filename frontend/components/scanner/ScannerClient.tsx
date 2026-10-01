"use client";

import { useTranslations, useLocale } from "next-intl";
import { useState, useCallback, useEffect, useRef } from "react";
import dynamic from "next/dynamic";
import { Link } from "@/i18n/navigation";
import { Zap, Shield, Microscope, CheckCircle, AlertTriangle, ShieldAlert, Terminal, RefreshCw, FileDown, Sparkles, Copy, Check, Network, Cpu, Globe, Clock, Server, Lock, Unlock, X } from "lucide-react";
import { convertScanResultToScanReport } from "@/lib/report-data";
import AgentWorkflowGraph from "./AgentWorkflowGraph";
import { scanCoordinator, ScanType, ScanStatus, ScanResult, ScanState } from "@/lib/scanCoordinator";

const ReportGenerator = dynamic(() => import("@/components/report/ReportGenerator"), { ssr: false });

const SCAN_TYPES = [
  { key: "quick" as ScanType, icon: Zap, duration: "~3s", scanners: 4 },
  { key: "standard" as ScanType, icon: Shield, duration: "~8s", scanners: 10 },
  { key: "deep" as ScanType, icon: Microscope, duration: "~30s", scanners: 16 },
  { key: "autonomous" as ScanType, icon: Sparkles, duration: "~35s", scanners: 4 },
];

function gradeClass(grade: string): string {
  const g = (grade || "F").replace("+", "").toLowerCase();
  if (g === "a") return "grade-a";
  if (g === "b") return "grade-b";
  if (g === "c") return "grade-c";
  if (g === "d") return "grade-d";
  return "grade-f";
}

function scoreClass(score: number): string {
  if (score >= 80) return "score-good";
  if (score >= 65) return "score-ok";
  return "score-bad";
}

function localize(val: any, locale: string): string {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  if (typeof val === "object") {
    if (val[locale]) return String(val[locale]);
    if (locale === "fr" && val.fr) return String(val.fr);
    if (locale === "en" && val.en) return String(val.en);
    if (locale === "ar" && val.ar) return String(val.ar);
    if (val.fr) return String(val.fr);
    if (val.en) return String(val.en);
    if (val.ar) return String(val.ar);
    if (val.missing_header) return `[ABSENT] ${val.missing_header}`;
    try {
      return JSON.stringify(val, null, 2);
    } catch {
      return String(val);
    }
  }
  return String(val);
}

export default function ScannerClient() {
  const t = useTranslations("scanner");
  const locale = useLocale();
  const isAr = locale === "ar";
  const isFr = locale === "fr";

  const [scanState, setScanState] = useState<ScanState>(() => scanCoordinator.getState());
  const {
    url,
    scanType,
    status,
    progress,
    result,
    error,
    isAutonomousUnlocked,
    mandatCode: initialMandatCode,
    auditorSignature: initialAuditorSig,
  } = scanState;

  const [showViewerNotice, setShowViewerNotice] = useState(false);
  const [copiedStep, setCopiedStep] = useState<number | null>(null);

  // ── RoE & Mandat ANCS State ─────────────────────────────
  const [showRoeModal, setShowRoeModal] = useState(false);
  const [mandatCode, setMandatCode] = useState(initialMandatCode || "ANCS-2026");
  const [roeCheck1, setRoeCheck1] = useState(true);
  const [roeCheck2, setRoeCheck2] = useState(true);
  const [roeCheck3, setRoeCheck3] = useState(true);
  const [auditorSignature, setAuditorSignature] = useState(initialAuditorSig || "Admin ANCS");
  const [mandatError, setMandatError] = useState("");

  const copyCommand = (commands: string, stepNum: number) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(commands);
      setCopiedStep(stepNum);
      setTimeout(() => setCopiedStep(null), 2000);
    }
  };

  // Authenticated User State
  const [loggedUser, setLoggedUser] = useState<{
    id: number;
    email: string;
    fullName: string;
    role: "admin" | "auditor" | "viewer";
    organization: string;
  }>({
    id: 2,
    email: "yosri.hamdouni@finances.gov.tn",
    fullName: "Yosri Hamdouni",
    role: "auditor",
    organization: "Ministère des Finances",
  });

  useEffect(() => {
    try {
      const raw = localStorage.getItem("cyberscore_user");
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed) {
          const safeName = parsed.fullName || parsed.full_name || parsed.name || (parsed.email ? parsed.email.split("@")[0] : "Auditeur");
          const safeOrg = typeof parsed.organization === "string" ? parsed.organization : parsed.organization_name || "Ministère des Finances";
          const safeRole = parsed.role === "admin" || parsed.role === "auditor" || parsed.role === "viewer" ? parsed.role : "auditor";
          setLoggedUser({
            id: parsed.id || 2,
            email: parsed.email || "yosri.hamdouni@finances.gov.tn",
            fullName: safeName,
            role: safeRole,
            organization: safeOrg,
          });
        }
      }
    } catch {}
  }, []);

  // Check for ?site=, ?target=, or ?domain= query parameter from alerts/links
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const siteParam = params.get("site") || params.get("target") || params.get("domain");
      if (siteParam) {
        const fullUrl = siteParam.startsWith("http") ? siteParam : `https://${siteParam}`;
        scanCoordinator.setUrl(fullUrl);
      }
    }
  }, []);

  // Subscribe to ScanCoordinator singleton (survives route/locale changes)
  useEffect(() => {
    const unsubscribe = scanCoordinator.subscribe((newState) => {
      setScanState(newState);
      if (newState.mandatCode) setMandatCode(newState.mandatCode);
      if (newState.auditorSignature) setAuditorSignature(newState.auditorSignature);
    });
    return unsubscribe;
  }, []);

  const setUrl = (newUrl: string) => {
    scanCoordinator.setUrl(newUrl);
  };

  const setScanType = (type: ScanType) => {
    scanCoordinator.setScanType(type);
  };

  // ── Handle Mandat ANCS + RoE Validation ───────────────────
  const handleValidateMandat = () => {
    setMandatError("");
    const code = mandatCode.trim().toUpperCase();
    if (!code || (!code.startsWith("ANCS-"))) {
      setMandatError(
        isAr ? "رمز المأذونية غير صالح. يجب أن يبدأ بـ ANCS- (مثال: ANCS-2026)"
        : isFr ? "Code de mandat invalide. Doit commencer par ANCS- (ex: ANCS-2026)"
        : "Invalid mandate code. Must start with ANCS- (e.g. ANCS-2026)"
      );
      return;
    }
    if (!roeCheck1 || !roeCheck2 || !roeCheck3) {
      setMandatError(
        isAr ? "يجب الموافقة على جميع بنود قواعد المشاركة (RoE) الثلاثة"
        : isFr ? "Vous devez accepter les 3 clauses des Règles d'Engagement (RoE)"
        : "You must accept all 3 Rules of Engagement (RoE) clauses"
      );
      return;
    }
    const sigName = auditorSignature.trim() || loggedUser.fullName;
    if (!sigName) {
      setMandatError(
        isAr ? "التوقيع الرقمي مطلوب"
        : isFr ? "La signature numérique est requise"
        : "Digital signature is required"
      );
      return;
    }
    // All checks pass
    scanCoordinator.unlockAutonomous(code, sigName);
    setShowRoeModal(false);
    setMandatError("");
    if (url.trim()) {
      runScan("autonomous", code, sigName);
    }
  };

  const runScan = async (targetScanType: ScanType = scanType, authCode?: string, authSig?: string) => {
    if (!url.trim()) return;

    // RBAC Check: Viewers cannot launch scans
    if (loggedUser.role === "viewer") {
      setShowViewerNotice(true);
      return;
    }

    // Autonomous Audit Gate: Require RoE + Mandat ANCS
    if (targetScanType === "autonomous" && !isAutonomousUnlocked) {
      setShowRoeModal(true);
      return;
    }

    await scanCoordinator.startScan({
      url: url.trim(),
      scanType: targetScanType,
      authCode: authCode || mandatCode,
      authSig: authSig || auditorSignature,
      loggedUserEmail: loggedUser.email,
      loggedUserName: loggedUser.fullName,
      loggedUserRole: loggedUser.role,
    });
  };

  const startScan = () => {
    runScan(scanType);
  };

  const resetScan = () => {
    scanCoordinator.resetScan();
  };

  const getCategoryLabel = (cat: { category: string; label_ar?: string; label_fr?: string; label_en?: string }) => {
    if (locale === "ar" && cat.label_ar) return cat.label_ar;
    if (locale === "fr" && cat.label_fr) return cat.label_fr;
    if (locale === "en" && cat.label_en) return cat.label_en;
    return cat.label_fr || cat.label_ar || cat.label_en || cat.category;
  };

  const getSeverityLabel = (sev: string) => {
    const s = sev.toLowerCase();
    if (isAr) {
      if (s === "critical") return "حرج";
      if (s === "high") return "عالي";
      if (s === "medium") return "متوسط";
      if (s === "low") return "منخفض";
      return "معلومة";
    }
    if (isFr) {
      if (s === "critical") return "CRITIQUE";
      if (s === "high") return "ÉLEVÉ";
      if (s === "medium") return "MOYEN";
      if (s === "low") return "FAIBLE";
      return "INFO";
    }
    return s.toUpperCase();
  };

  return (
    <div>
      {/* RBAC Accreditation Scope Header */}
      <div
        style={{
          background: "var(--bg-secondary)",
          border: "1px solid var(--border-primary)",
          borderInlineStart: `3px solid ${
            loggedUser.role === "admin" ? "#ef4444" : loggedUser.role === "auditor" ? "#0284c7" : "#64748b"
          }`,
          padding: "10px 16px",
          marginBottom: "20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "10px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span
            style={{
              padding: "2px 8px",
              fontSize: "9px",
              fontFamily: "monospace",
              fontWeight: 800,
              textTransform: "uppercase",
              color: loggedUser.role === "admin" ? "#ef4444" : loggedUser.role === "auditor" ? "#0284c7" : "#64748b",
              background:
                loggedUser.role === "admin"
                  ? "rgba(239, 68, 68, 0.1)"
                  : loggedUser.role === "auditor"
                  ? "rgba(2, 132, 199, 0.1)"
                  : "rgba(100, 116, 139, 0.1)",
              border: `1px solid ${
                loggedUser.role === "admin" ? "#ef4444" : loggedUser.role === "auditor" ? "#0284c7" : "#64748b"
              }`,
              borderRadius: "2px",
            }}
          >
            {loggedUser.role === "admin"
              ? isAr ? "مدير عام ANCS" : "ADMIN ANCS"
              : loggedUser.role === "auditor"
              ? isAr ? "مدقق أمني RSSI" : "AUDITEUR RSSI"
              : isAr ? "ملاحظ عام (قراءة فقط)" : "OBSERVATEUR (LECTURE SEULE)"}
          </span>
          <span style={{ fontSize: "11.5px", color: "var(--text-secondary)" }}>
            {loggedUser.role === "admin"
              ? isAr
                ? "إشراف وطني شامل: تدقيق مصرح لجميع النطاقات الحكومية (120 موقعاً)"
                : isFr
                ? "Supervision Nationale : Audits autorisés sans restriction sur l'ensemble des 120 domaines .gov.tn"
                : "National Oversight: Full scanning authorization across all 120 .gov.tn state domains"
              : loggedUser.role === "auditor"
              ? isAr
                ? `نطاق التدقيق المصرح: ${loggedUser.organization} • مستوى الأهلية 2 (فحص سريع ومعمق)`
                : isFr
                ? `Périmètre Habilité : ${loggedUser.organization} • Accréditation Niveau 2 (Quick / Standard / Deep)`
                : `Authorized Scope: ${loggedUser.organization} • Level 2 Clearance (Quick / Standard / Deep)`
              : isAr
              ? "وضع المشاهدة والاستشارة: الفحص الفعلي مقصور على ضباط السلامة والمشرفين"
              : isFr
              ? "Mode Consultation Seule : Le lancement d'audits est réservé aux Officiers RSSI et Administrateurs."
              : "Read-Only Mode: Active scanning is restricted to authorized RSSI Officers and Admins."}
          </span>
        </div>

        <div style={{ fontSize: "11px", color: "var(--text-tertiary)", fontFamily: "monospace" }}>
          {loggedUser.email}
        </div>
      </div>

      {/* Modal / Alert when Viewer clicks Start Scan */}
      {showViewerNotice && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999,
            padding: "20px",
            backdropFilter: "blur(4px)",
          }}
        >
          <div
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid #64748b",
              maxWidth: "540px",
              width: "100%",
              padding: "28px 24px",
              boxShadow: "0 10px 40px rgba(0,0,0,0.5)",
              textAlign: "center",
            }}
          >
            <div
              style={{
                width: "48px",
                height: "48px",
                borderRadius: "50%",
                background: "rgba(100, 116, 139, 0.15)",
                border: "1px solid #64748b",
                color: "#94a3b8",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "0 auto 16px auto",
              }}
            >
              <ShieldAlert size={28} />
            </div>

            <div style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8", letterSpacing: "2px", textTransform: "uppercase", marginBottom: "6px" }}>
              RBAC // PERMISSION DENIED (VIEWER ROLE)
            </div>

            <h3 style={{ fontSize: "17px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "10px" }}>
              {isAr ? "إجراء مقيد لحسابات التدقيق" : isFr ? "Action Restreinte aux Officiers d'Audit" : "Action Restricted to Audit Officers"}
            </h3>

            <p style={{ fontSize: "12.5px", color: "var(--text-secondary)", lineHeight: "1.6", marginBottom: "20px" }}>
              {isAr
                ? "حسابك الحالي مسجل بصفة 'ملاحظ عام' (قراءة فقط). وفقاً لسياسة الأمان الصادرة عن ANCS، يتطلب تشغيل مسح أمني جديد حساب 'مدقق RSSI' أو 'مدير عام'."
                : isFr
                ? "Votre compte est connecté avec le rôle 'Observateur' (lecture seule). Conformément aux directives ANCS, le déclenchement d'un audit de sécurité actif requiert un profil 'Auditeur RSSI' ou 'Admin ANCS'."
                : "Your account has 'Viewer' status (read-only). Under ANCS security policies, triggering active penetration scans requires an 'Auditor' or 'Admin' clearance."}
            </p>

            <div style={{ display: "flex", gap: "10px", justifyContent: "center" }}>
              <button
                onClick={() => setShowViewerNotice(false)}
                style={{
                  padding: "8px 18px",
                  background: "var(--bg-tertiary)",
                  border: "1px solid var(--border-primary)",
                  color: "var(--text-primary)",
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                {isAr ? "إغلاق" : isFr ? "Compris" : "Close"}
              </button>
              <button
                onClick={() => {
                  const auditorSession = {
                    id: 2,
                    email: "yosri.hamdouni@finances.gov.tn",
                    fullName: "Yosri Hamdouni",
                    role: "auditor" as const,
                    organization: "Ministère des Finances",
                    isActive: true,
                  };
                  localStorage.setItem("cyberscore_user", JSON.stringify(auditorSession));
                  setLoggedUser(auditorSession);
                  setShowViewerNotice(false);
                }}
                style={{
                  padding: "8px 18px",
                  background: "var(--color-accent)",
                  border: "none",
                  color: "#ffffff",
                  fontSize: "12px",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                {isAr ? "التبديل إلى حساب مدقق Finances" : isFr ? "Basculer en Auditeur Finances" : "Switch to Auditor"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── RoE & Mandat ANCS Modal ───────────────────── */}
      {showRoeModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0, 0, 0, 0.8)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 99999,
            padding: "20px",
            backdropFilter: "blur(6px)",
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowRoeModal(false); }}
        >
          <div
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-primary)",
              borderTop: "3px solid #ef4444",
              maxWidth: "560px",
              width: "100%",
              maxHeight: "90vh",
              overflowY: "auto",
              padding: "0",
            }}
          >
            {/* Header */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "16px 20px",
                borderBottom: "1px solid var(--border-primary)",
                background: "var(--bg-tertiary)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <Lock size={16} style={{ color: "#ef4444" }} />
                <div>
                  <div style={{ fontSize: "13px", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "0.5px" }}>
                    {isAr ? "بوابة التحكم في الوصول — ANCS" : "CONTRÔLE D'ACCÈS — ANCS"}
                  </div>
                  <div style={{ fontSize: "10px", color: "var(--text-tertiary)", fontFamily: "monospace", marginTop: "2px" }}>
                    {isAr ? "قواعد المشاركة (RoE) • التدقيق الذاتي المتعدد الوكلاء" : "Règles d'Engagement (RoE) • Audit Autonome Multi-Agents"}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setShowRoeModal(false)}
                style={{ background: "none", border: "none", color: "var(--text-secondary)", cursor: "pointer", padding: "4px" }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Body */}
            <div style={{ padding: "20px" }}>
              {/* Classification Banner */}
              <div
                style={{
                  background: "rgba(239, 68, 68, 0.06)",
                  border: "1px solid rgba(239, 68, 68, 0.2)",
                  padding: "8px 12px",
                  marginBottom: "18px",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <ShieldAlert size={14} style={{ color: "#ef4444", flexShrink: 0 }} />
                <span style={{ fontSize: "10px", fontFamily: "monospace", fontWeight: 700, color: "#ef4444", textTransform: "uppercase", letterSpacing: "1px" }}>
                  {isAr ? "TLP:AMBER — توزيع مقيّد" : "TLP:AMBER — DIFFUSION RESTREINTE"}
                </span>
              </div>

              {/* Code de Mandat */}
              <div style={{ marginBottom: "18px" }}>
                <label style={{ display: "block", fontSize: "11px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  {isAr ? "رمز المأذونية الرسمية ANCS" : "CODE DE MANDAT OFFICIEL ANCS"}
                </label>
                <input
                  type="text"
                  value={mandatCode}
                  onChange={(e) => setMandatCode(e.target.value)}
                  placeholder={isAr ? "أدخل الرمز (مثال: ANCS-2026)" : "Saisir le code (ex: ANCS-2026)"}
                  dir="ltr"
                  style={{
                    width: "100%",
                    padding: "10px 12px",
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border-primary)",
                    color: "var(--text-primary)",
                    fontSize: "13px",
                    fontFamily: "monospace",
                    fontWeight: 600,
                    letterSpacing: "1.5px",
                    textTransform: "uppercase",
                    outline: "none",
                    boxSizing: "border-box",
                  }}
                />
              </div>

              {/* Separator */}
              <div style={{ borderBottom: "1px solid var(--border-primary)", marginBottom: "16px" }} />

              {/* RoE Clauses Title */}
              <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "12px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                {isAr ? "بنود قواعد المشاركة (RoE) — إلزامية" : "CLAUSES RÈGLES D'ENGAGEMENT (RoE) — OBLIGATOIRES"}
              </div>

              {/* Clause 1 */}
              <label
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "10px",
                  padding: "10px 12px",
                  marginBottom: "8px",
                  background: roeCheck1 ? "rgba(34,197,94,0.05)" : "var(--bg-tertiary)",
                  border: `1px solid ${roeCheck1 ? "rgba(34,197,94,0.3)" : "var(--border-primary)"}`,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                <input
                  type="checkbox"
                  checked={roeCheck1}
                  onChange={(e) => setRoeCheck1(e.target.checked)}
                  style={{ marginTop: "2px", accentColor: "#22c55e", flexShrink: 0 }}
                />
                <span style={{ fontSize: "11.5px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                  {isAr
                    ? "أشهد أنني أحمل تفويضاً رسمياً للتدقيق صادراً عن الوكالة الوطنية للسلامة المعلوماتية (ANCS) أو الوزارة المشرفة."
                    : "Je certifie détenir un mandat officiel d'audit délivré par l'ANCS ou le ministère de tutelle."}
                </span>
              </label>

              {/* Clause 2 */}
              <label
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "10px",
                  padding: "10px 12px",
                  marginBottom: "8px",
                  background: roeCheck2 ? "rgba(34,197,94,0.05)" : "var(--bg-tertiary)",
                  border: `1px solid ${roeCheck2 ? "rgba(34,197,94,0.3)" : "var(--border-primary)"}`,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                <input
                  type="checkbox"
                  checked={roeCheck2}
                  onChange={(e) => setRoeCheck2(e.target.checked)}
                  style={{ marginTop: "2px", accentColor: "#22c55e", flexShrink: 0 }}
                />
                <span style={{ fontSize: "11.5px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                  {isAr
                    ? "أقرّ بأن هذا الفحص النشط يحترم النطاق الزمني المرخّص ولن يعطّل استمرارية الخدمة."
                    : "J'atteste que cette sonde active respecte la plage horaire autorisée et ne perturbera pas la continuité de service."}
                </span>
              </label>

              {/* Clause 3 */}
              <label
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "10px",
                  padding: "10px 12px",
                  marginBottom: "16px",
                  background: roeCheck3 ? "rgba(34,197,94,0.05)" : "var(--bg-tertiary)",
                  border: `1px solid ${roeCheck3 ? "rgba(34,197,94,0.3)" : "var(--border-primary)"}`,
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
              >
                <input
                  type="checkbox"
                  checked={roeCheck3}
                  onChange={(e) => setRoeCheck3(e.target.checked)}
                  style={{ marginTop: "2px", accentColor: "#22c55e", flexShrink: 0 }}
                />
                <span style={{ fontSize: "11.5px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                  {isAr
                    ? "ألتزم بتصنيف النتائج تحت مستوى TLP:AMBER (توزيع مقيّد)."
                    : "Je m'engage à classifier les résultats sous TLP:AMBER (diffusion restreinte)."}
                </span>
              </label>

              {/* Separator */}
              <div style={{ borderBottom: "1px solid var(--border-primary)", marginBottom: "16px" }} />

              {/* Digital Signature */}
              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "11px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  {isAr ? "التوقيع الرقمي للضابط" : "SIGNATURE NUMÉRIQUE DE L'OFFICIER"}
                </label>
                <input
                  type="text"
                  value={auditorSignature}
                  onChange={(e) => setAuditorSignature(e.target.value)}
                  placeholder={loggedUser.fullName}
                  dir={isAr ? "rtl" : "ltr"}
                  style={{
                    width: "100%",
                    padding: "10px 12px",
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border-primary)",
                    color: "var(--text-primary)",
                    fontSize: "12px",
                    outline: "none",
                    boxSizing: "border-box",
                  }}
                />
                <div style={{ fontSize: "10px", color: "var(--text-tertiary)", marginTop: "4px", fontFamily: "monospace" }}>
                  {isAr
                    ? `${loggedUser.organization} • ${loggedUser.email} • ${new Date().toLocaleDateString("ar-TN")}`
                    : `${loggedUser.organization} • ${loggedUser.email} • ${new Date().toLocaleDateString("fr-TN")}`}
                </div>
              </div>

              {/* Error Message */}
              {mandatError && (
                <div
                  style={{
                    background: "rgba(239, 68, 68, 0.08)",
                    border: "1px solid rgba(239, 68, 68, 0.3)",
                    padding: "8px 12px",
                    marginBottom: "14px",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <AlertTriangle size={13} style={{ color: "#ef4444", flexShrink: 0 }} />
                  <span style={{ fontSize: "11px", color: "#ef4444" }}>{mandatError}</span>
                </div>
              )}

              {/* Actions */}
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "4px" }}>
                <button
                  onClick={() => setShowRoeModal(false)}
                  style={{
                    padding: "9px 18px",
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border-primary)",
                    color: "var(--text-secondary)",
                    fontSize: "12px",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  {isAr ? "إلغاء" : "Annuler"}
                </button>
                <button
                  onClick={handleValidateMandat}
                  disabled={!mandatCode.trim() || !roeCheck1 || !roeCheck2 || !roeCheck3}
                  style={{
                    padding: "9px 22px",
                    background: (!mandatCode.trim() || !roeCheck1 || !roeCheck2 || !roeCheck3) ? "rgba(239,68,68,0.3)" : "#ef4444",
                    border: "none",
                    color: "#ffffff",
                    fontSize: "12px",
                    fontWeight: 800,
                    cursor: (!mandatCode.trim() || !roeCheck1 || !roeCheck2 || !roeCheck3) ? "not-allowed" : "pointer",
                    textTransform: "uppercase",
                    letterSpacing: "0.5px",
                    opacity: (!mandatCode.trim() || !roeCheck1 || !roeCheck2 || !roeCheck3) ? 0.5 : 1,
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                >
                  <Shield size={13} />
                  {isAr ? "توثيق وبدء التدقيق" : "Valider & Autoriser l'Audit"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Idle State ──────────────────────────────────── */}
      {status === "idle" && (
        <>
          <div className="scanner-hero">
            <h1>{t("title")}</h1>
            <p>{t("description")}</p>

            <div className="scanner-input-group">
              <input
                type="url"
                className="input"
                placeholder="https://www.example.gov.tn"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && startScan()}
                dir="ltr"
              />
              <button
                className="btn btn-primary"
                onClick={startScan}
                disabled={!url.trim()}
              >
                {t("startScan")}
              </button>
            </div>
          </div>

          <div className="scan-type-selector">
            {SCAN_TYPES.map((st) => {
              const Icon = st.icon;
              const isAutonomousCard = st.key === "autonomous";
              return (
                <div
                  key={st.key}
                  className={`scan-type-card ${scanType === st.key ? "selected" : ""}`}
                  onClick={() => {
                    if (isAutonomousCard && !isAutonomousUnlocked) {
                      setShowRoeModal(true);
                      return;
                    }
                    setScanType(st.key);
                  }}
                >
                  <span className="icon">
                    <Icon size={16} strokeWidth={1.5} />
                  </span>
                  <span className="name">{t(`scanType_${st.key}`)}</span>
                  <span className="meta">{st.duration}</span>
                  {isAutonomousCard && (
                    <span
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        marginInlineStart: "6px",
                        color: isAutonomousUnlocked ? "var(--color-success)" : "var(--text-tertiary)",
                      }}
                    >
                      <span
                        style={{
                          width: "6px",
                          height: "6px",
                          borderRadius: "50%",
                          background: isAutonomousUnlocked ? "#22c55e" : "#f59e0b",
                          boxShadow: isAutonomousUnlocked ? "0 0 6px rgba(34, 197, 94, 0.6)" : "none",
                        }}
                      />
                      {isAutonomousUnlocked
                        ? (isAr ? "مصرّح" : "Mandat validé")
                        : (isAr ? "مأذونية" : "Mandat requis")}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {/* ── Scanning State ──────────────────────────────── */}
      {status === "scanning" && (
        <div
          className="scan-progress"
          style={scanType === "autonomous" ? { maxWidth: "860px", width: "100%" } : undefined}
        >
          <div className="scan-progress-value">{Math.round(progress)}%</div>
          <div className="scan-progress-label">
            {scanType === "autonomous"
              ? isAr
                ? "جاري تنفيذ التدقيق الذاتي متعدد الوكلاء عبر الذكاء الاصطناعي السيادي..."
                : isFr
                ? "Orchestration multi-agents autonome en cours via l'IA souveraine..."
                : "Autonomous multi-agent audit running via sovereign AI..."
              : t("scanning")}
          </div>
          <div className="linear-progress">
            <div
              className="linear-progress-fill"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="scan-progress-target" dir="ltr">{url}</div>

          {/* Autonomous Multi-Agent Live Execution Graph */}
          {scanType === "autonomous" && (
            <AgentWorkflowGraph
              progress={progress}
              locale={locale}
              target={url}
            />
          )}
        </div>
      )}

      {/* ── Error State ─────────────────────────────────── */}
      {status === "error" && (
        <div className="text-center" style={{ padding: "var(--space-3xl) 0" }}>
          <div style={{ color: "var(--color-critical)", fontWeight: 600, marginBottom: "var(--space-lg)" }}>
            {error}
          </div>
          <button
            className="btn btn-secondary"
            onClick={resetScan}
          >
            {t("tryAgain")}
          </button>
        </div>
      )}

      {/* ── Results State ───────────────────────────────── */}
      {status === "complete" && result && (
        <div>
          {/* Score Header */}
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: "var(--space-lg)",
              padding: "var(--space-2xl) 0 var(--space-xl)",
              borderBottom: "1px solid var(--border-primary)",
              marginBottom: "var(--space-xl)",
            }}
          >
            <div style={{ display: "flex", alignItems: "baseline", gap: "var(--space-lg)" }}>
              <div className="score-display">
                <span className={`score-number ${scoreClass(result.total_score)}`}>
                  {result.total_score.toFixed(0)}
                </span>
                <span className="score-max">/100</span>
              </div>
              <span className={`grade-badge ${gradeClass(result.grade)}`}>
                {result.grade}
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                <span className="text-mono" style={{ fontSize: "var(--text-xs)", color: "var(--text-tertiary)" }} dir="ltr">
                  {result.target}
                </span>
                <span className="text-mono" style={{ fontSize: "var(--text-xs)", color: "var(--text-tertiary)" }}>
                  {result.duration_ms}ms · {result.total_findings} {isAr ? "نتيجة" : isFr ? "découvertes" : "findings"}
                </span>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
              <Link
                href={`/assistant?site=${encodeURIComponent(result.target.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0])}`}
                className="btn btn-secondary"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  border: "1px solid rgba(99, 102, 241, 0.4)",
                  color: "#6366f1",
                  background: "rgba(99, 102, 241, 0.05)",
                  fontWeight: 600
                }}
              >
                <Sparkles size={14} color="#6366f1" />
                <span>{isAr ? "استشارة أمينة 🤖" : isFr ? "Consulter Amina 🤖" : "Ask Amina 🤖"}</span>
              </Link>
              <ReportGenerator
                siteUrl={result.target.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]}
                reportData={convertScanResultToScanReport(result)}
                variant="button"
              />
              <button
                className="btn btn-secondary"
                onClick={resetScan}
                style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
              >
                <RefreshCw size={14} />
                <span>{t("scanAnother")}</span>
              </button>
            </div>
          </div>

          {/* Cryptographic SHA-256 Seal Banner */}
          {result.sha256_hash && (
            <div
              style={{
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-primary)",
                borderLeft: "4px solid var(--color-accent, #3b82f6)",
                borderRadius: "var(--radius-md, 8px)",
                padding: "14px 20px",
                marginBottom: "20px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "12px",
                boxShadow: "var(--shadow-card, none)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span style={{ fontSize: "22px" }}>🛡️</span>
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--color-accent, #2563eb)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "2px" }}>
                    {isAr ? "ختم إثبات التدقيق السيادي (SHA-256 CERTIFIED)" : isFr ? "SCEAU D'INTÉGRITÉ CRYPTOGRAPHIQUE SHA-256" : "CRYPTOGRAPHIC INTEGRITY SEAL (SHA-256)"}
                  </div>
                  <div style={{ fontSize: "11.5px", fontFamily: "monospace", color: "var(--text-secondary)", wordBreak: "break-all" }}>
                    {result.sha256_hash}
                  </div>
                </div>
              </div>
              <span
                style={{
                  fontSize: "11px",
                  padding: "4px 10px",
                  borderRadius: "4px",
                  background: "rgba(34, 197, 94, 0.12)",
                  color: "#16a34a",
                  fontWeight: 700,
                  border: "1px solid rgba(34, 197, 94, 0.3)",
                }}
              >
                {isAr ? "✓ غير قابل للتعديل" : isFr ? "✓ IMMUABLE" : "✓ IMMUTABLE"}
              </span>
            </div>
          )}

          {/* Severity Summary */}
          <div className="stat-grid">
            {[
              { label: isAr ? "حرجة" : isFr ? "Critiques" : "Critical", count: result.critical_count, severity: "critical" },
              { label: isAr ? "عالية" : isFr ? "Élevées" : "High", count: result.high_count, severity: "high" },
              { label: isAr ? "متوسطة" : isFr ? "Moyennes" : "Medium", count: result.medium_count, severity: "medium" },
              { label: isAr ? "منخفضة" : isFr ? "Faibles" : "Low", count: result.low_count, severity: "low" },
            ].map((s) => (
              <div key={s.severity} className="stat-card">
                <div className="stat-value">{s.count}</div>
                <div className="stat-label">
                  <span className={`severity-tag ${s.severity}`}>{s.label}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Category Breakdown */}
          {result.category_breakdown && result.category_breakdown.length > 0 && (
            <div className="section mt-2xl">
              <div className="section-header">
                <div className="section-title">{t("categoryBreakdown")}</div>
              </div>
              {result.category_breakdown.map((cat) => {
                const pct = (cat.score / cat.max_score) * 100;
                return (
                  <div key={cat.category} className="sector-row">
                    <span className="sector-name">{getCategoryLabel(cat)}</span>
                    <div className="sector-bar-container">
                      <div className="sector-bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                    <span className={`sector-score ${scoreClass(pct)}`}>
                      {cat.score.toFixed(1)}/{cat.max_score}
                    </span>
                  </div>
                );
              })}
            </div>
          )}

          {/* OS & Network Fingerprint Card (Advanced Reconnaissance) */}
          {(result.os_detection || result.ipv6_address || result.web_surface?.page_title) && (
            <div className="section mt-2xl">
              <div
                style={{
                  border: "1px solid var(--border-primary)",
                  borderRadius: "var(--radius-lg, 12px)",
                  backgroundColor: "var(--bg-secondary)",
                  boxShadow: "var(--shadow-card, none)",
                  padding: "20px",
                  borderLeft: "4px solid var(--color-accent, #3b82f6)",
                }}
              >
                <div
                  className="section-header"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "8px",
                    borderBottom: "1px solid var(--border-secondary)",
                    paddingBottom: "12px",
                    marginBottom: "16px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <Cpu size={20} style={{ color: "var(--color-accent, #3b82f6)" }} />
                    <div>
                      <div className="section-title" style={{ fontSize: "16px", fontWeight: 700, color: "var(--text-primary)" }}>
                        {isAr ? "البصمة التقنية للنظام والشبكة (Agent 1 Recon)" : isFr ? "Empreinte Système & Télémétrie Réseau (Agent Recon)" : "OS & Network Fingerprint (Recon Agent)"}
                      </div>
                      <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                        {isAr ? "تحليل حقول بروتوكول IP TTL والتعرف على النواة والمسار" : isFr ? "Analyse passive/active des paquets TCP/IP TTL et corrélation multi-couches" : "Passive & active TCP/IP TTL packet analysis with multi-layer correlation"}
                      </div>
                    </div>
                  </div>
                  {result.os_detection?.confidence && (
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: 600,
                        padding: "4px 10px",
                        borderRadius: "9999px",
                        backgroundColor: "var(--color-accent-muted, rgba(59, 130, 246, 0.1))",
                        color: "var(--color-accent, #2563eb)",
                        border: "1px solid rgba(59, 130, 246, 0.25)",
                      }}
                    >
                      {isAr ? `دقة التحديد: ${result.os_detection.confidence}%` : `Indice de Confiance : ${result.os_detection.confidence}%`}
                    </span>
                  )}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "14px" }}>
                  {/* OS Detected */}
                  {result.os_detection && (
                    <div
                      style={{
                        backgroundColor: "var(--bg-tertiary)",
                        borderRadius: "var(--radius-md, 8px)",
                        padding: "16px",
                        border: "1px solid var(--border-secondary)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                          color: "var(--text-secondary)",
                          marginBottom: "6px",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          fontWeight: 600,
                        }}
                      >
                        <Server size={14} style={{ color: "#8b5cf6" }} />
                        <span>{isAr ? "نظام التشغيل المكتشف" : isFr ? "Système d'Exploitation" : "Operating System"}</span>
                      </div>
                      <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "4px" }}>
                        {result.os_detection.os_detailed || result.os_detection.os_family}
                      </div>
                      <div style={{ fontSize: "11.5px", color: "var(--text-secondary)" }}>
                        {isAr ? `عائلة النظام: ${result.os_detection.os_family}` : isFr ? `Famille : ${result.os_detection.os_family} • Méthode : ${result.os_detection.method || "TTL Heuristique"}` : `Family: ${result.os_detection.os_family}`}
                      </div>
                    </div>
                  )}

                  {/* Network Telemetry */}
                  {result.os_detection?.ttl_received && (
                    <div
                      style={{
                        backgroundColor: "var(--bg-tertiary)",
                        borderRadius: "var(--radius-md, 8px)",
                        padding: "16px",
                        border: "1px solid var(--border-secondary)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                          color: "var(--text-secondary)",
                          marginBottom: "6px",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          fontWeight: 600,
                        }}
                      >
                        <Network size={14} style={{ color: "var(--color-accent, #3b82f6)" }} />
                        <span>{isAr ? "المقاييس الشبكية والمكانية" : isFr ? "Télémétrie Réseau & Sauts" : "Network Telemetry"}</span>
                      </div>
                      <div style={{ display: "flex", gap: "16px", alignItems: "baseline", marginTop: "4px" }}>
                        <div>
                          <div style={{ fontSize: "20px", fontWeight: 700, color: "var(--color-accent, #2563eb)" }}>
                            {result.os_detection.ttl_received}
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>IP TTL</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "20px", fontWeight: 700, color: "#16a34a" }}>
                            {result.os_detection.hops_distance ?? "?"}
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>
                            {isAr ? "قفزات (Hops)" : "Sauts (Hops)"}
                          </div>
                        </div>
                        {result.os_detection.rtt_ms && (
                          <div>
                            <div style={{ fontSize: "20px", fontWeight: 700, color: "#d97706" }}>
                              {result.os_detection.rtt_ms} ms
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-tertiary)", marginTop: "2px" }}>RTT Latence</div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Dual-Stack IPv6 */}
                  {result.ipv6_address && (
                    <div
                      style={{
                        backgroundColor: "var(--bg-tertiary)",
                        borderRadius: "var(--radius-md, 8px)",
                        padding: "16px",
                        border: "1px solid var(--border-secondary)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                          color: "var(--text-secondary)",
                          marginBottom: "6px",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          fontWeight: 600,
                        }}
                      >
                        <Globe size={14} style={{ color: "#0284c7" }} />
                        <span>{isAr ? "عنوان IPv6 المزدوج" : isFr ? "Résolution Dual-Stack IPv6" : "Dual-Stack IPv6"}</span>
                      </div>
                      <div className="text-mono" style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-accent, #2563eb)", wordBreak: "break-all" }}>
                        {result.ipv6_address}
                      </div>
                      <div style={{ fontSize: "11.5px", color: "#16a34a", marginTop: "6px", display: "flex", alignItems: "center", gap: "4px", fontWeight: 500 }}>
                        <Check size={13} />
                        <span>{isAr ? "سجل AAAA نشط ومعتمد" : isFr ? "Enregistrement AAAA public actif" : "Public AAAA record active"}</span>
                      </div>
                    </div>
                  )}

                  {/* Web Surface Metadata */}
                  {result.web_surface?.page_title && (
                    <div
                      style={{
                        backgroundColor: "var(--bg-tertiary)",
                        borderRadius: "var(--radius-md, 8px)",
                        padding: "16px",
                        border: "1px solid var(--border-secondary)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.5px",
                          color: "var(--text-secondary)",
                          marginBottom: "6px",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          fontWeight: 600,
                        }}
                      >
                        <Globe size={14} style={{ color: "#db2777" }} />
                        <span>{isAr ? "عنوان الصفحة والطرق المتاحة" : isFr ? "Surface Web & Titre HTML" : "Web Surface"}</span>
                      </div>
                      <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)", fontStyle: "italic", marginBottom: "4px" }}>
                        &ldquo;{result.web_surface.page_title}&rdquo;
                      </div>
                      {result.web_surface.http_methods && result.web_surface.http_methods.length > 0 && (
                        <div style={{ fontSize: "11.5px", color: "var(--text-secondary)" }}>
                          {isAr ? "طرق HTTP:" : "Méthodes :"} {result.web_surface.http_methods.join(", ")}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Software Obsolescence & EOL Technical Debt Alert */}
          {result.software_obsolescence && result.software_obsolescence.length > 0 && (
            <div className="section mt-2xl">
              <div
                style={{
                  border: "1px solid rgba(239, 68, 68, 0.35)",
                  borderRadius: "var(--radius-lg, 12px)",
                  backgroundColor: "var(--bg-secondary)",
                  boxShadow: "var(--shadow-card, none)",
                  padding: "20px",
                  borderLeft: "4px solid #ef4444",
                }}
              >
                <div
                  className="section-header"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "8px",
                    borderBottom: "1px solid var(--border-secondary)",
                    paddingBottom: "12px",
                    marginBottom: "16px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <Clock size={20} style={{ color: "#ef4444" }} />
                    <div>
                      <div className="section-title" style={{ fontSize: "16px", fontWeight: 700, color: "var(--text-primary)" }}>
                        {isAr ? "البرمجيات المتقادمة ومنتهية الدعم (Dette Technique & EOL)" : isFr ? "Obsolescence Logicielle & Composants en Fin de Vie (EOL)" : "Software Obsolescence & End-Of-Life (EOL)"} ({result.software_obsolescence.length})
                      </div>
                      <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                        {isAr ? "تحذير: المكونات القديمة غير المدعومة تشكل ثغرات أمنية هيكلية ذات قابلية استغلال عالية" : isFr ? "Composants historiques non maintenus présentant un risque critique d'exposition aux CVEs" : "Legacy unmaintained software components posing critical exploitation risk"}
                      </div>
                    </div>
                  </div>
                  <span className="severity-tag critical" style={{ fontSize: "11px", padding: "4px 10px" }}>
                    {isAr ? "مخاطر هيكلية حرجة" : isFr ? "Dette Technique Critique" : "Critical Technical Debt"}
                  </span>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px" }}>
                  {result.software_obsolescence.map((obs, idx) => (
                    <div
                      key={idx}
                      style={{
                        border: "1px solid var(--border-primary)",
                        borderRadius: "var(--radius-md, 8px)",
                        backgroundColor: "var(--bg-tertiary)",
                        padding: "16px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                        <div>
                          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--text-primary)" }}>
                            {obs.component}
                          </div>
                          <div className="text-mono" style={{ fontSize: "12px", color: "#dc2626", fontWeight: 600, marginTop: "2px" }}>
                            {obs.detected_string}
                          </div>
                        </div>
                        <span
                          style={{
                            fontSize: "11px",
                            fontWeight: 700,
                            padding: "3px 8px",
                            borderRadius: "4px",
                            backgroundColor: "rgba(239, 68, 68, 0.12)",
                            color: "#dc2626",
                            border: "1px solid rgba(239, 68, 68, 0.3)",
                          }}
                        >
                          {obs.eol_status}
                        </span>
                      </div>

                      <div style={{ display: "flex", gap: "12px", fontSize: "12px", color: "var(--text-secondary)", marginBottom: "12px" }}>
                        <span>📅 {isAr ? `سنة الإصدار: ${obs.release_year}` : isFr ? `Sortie en ${obs.release_year}` : `Released: ${obs.release_year}`}</span>
                        <span>⏳ <strong style={{ color: "#dc2626", fontWeight: 700 }}>{isAr ? `${obs.age_years} سنة تقادم` : isFr ? `${obs.age_years} ans d'ancienneté` : `${obs.age_years} years old`}</strong></span>
                      </div>

                      {obs.sample_cves && obs.sample_cves.length > 0 && (
                        <div style={{ marginBottom: "12px" }}>
                          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginBottom: "6px", fontWeight: 500 }}>
                            {isAr ? "أمثلة على الثغرات التاريخية (CVE) :" : isFr ? "CVE historiques associées :" : "Sample historical CVEs:"}
                          </div>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                            {obs.sample_cves.map((cve, cidx) => (
                              <span
                                key={cidx}
                                className="text-mono"
                                style={{
                                  fontSize: "11px",
                                  padding: "2px 8px",
                                  borderRadius: "4px",
                                  backgroundColor: "rgba(239, 68, 68, 0.08)",
                                  color: "#dc2626",
                                  border: "1px solid rgba(239, 68, 68, 0.25)",
                                  fontWeight: 600,
                                }}
                              >
                                {cve}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {obs.recommendation && (
                        <div style={{ fontSize: "12px", color: "var(--text-secondary)", borderTop: "1px solid var(--border-secondary)", paddingTop: "10px", marginTop: "8px", lineHeight: "1.5" }}>
                          💡 <strong style={{ color: "var(--text-primary)" }}>{isAr ? "التوصية:" : "Action recommandée :"}</strong> {obs.recommendation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Open Ports & Services (Agent 1 Network Reconnaissance) */}
          {result.open_ports && result.open_ports.length > 0 && (
            <div className="section mt-2xl">
              <div className="section-header" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <Network size={18} style={{ color: "var(--color-accent, #2563eb)" }} />
                <div className="section-title">
                  {isAr ? "المنافذ المفتوحة والخدمات المكتشفة" : isFr ? "Ports Ouverts & Bannières de Service (Agent Recon)" : "Open Ports & Service Banners (Recon Agent)"} ({result.open_ports.length})
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "12px", marginTop: "12px" }}>
                {result.open_ports.map((p, idx) => (
                  <div
                    key={idx}
                    style={{
                      border: p.is_risky ? "1px solid rgba(239, 68, 68, 0.4)" : "1px solid var(--border-primary)",
                      backgroundColor: p.is_risky ? "rgba(239, 68, 68, 0.04)" : "var(--bg-secondary)",
                      padding: "12px 14px",
                      borderRadius: "var(--radius-sm)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span className="text-mono" style={{ fontWeight: 700, fontSize: "14px", color: "var(--text-primary)" }}>
                          Port {p.port}/tcp
                        </span>
                        <span style={{ fontSize: "12px", color: "var(--text-secondary)", fontWeight: 500 }}>
                          ({p.service.toUpperCase()})
                        </span>
                      </div>
                      {p.is_risky ? (
                        <span className="severity-tag critical" style={{ fontSize: "10px", padding: "2px 6px" }}>
                          {isAr ? "خطر محتمل" : isFr ? "Service Exposé" : "High Risk"}
                        </span>
                      ) : (
                        <span className="severity-tag low" style={{ fontSize: "10px", padding: "2px 6px" }}>
                          {isAr ? "نشط" : isFr ? "Actif" : "Active"}
                        </span>
                      )}
                    </div>
                    {p.banner && (
                      <div
                        className="text-mono"
                        style={{
                          fontSize: "11px",
                          backgroundColor: "var(--bg-tertiary)",
                          color: "var(--text-primary)",
                          border: "1px solid var(--border-secondary)",
                          padding: "6px 8px",
                          borderRadius: "4px",
                          overflowX: "auto",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {p.banner}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Prioritized Remediation Roadmap (Agent 4 Orchestration) */}
          {result.remediation_roadmap && result.remediation_roadmap.length > 0 && (
            <div className="section mt-2xl">
              <div className="section-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "8px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <Terminal size={18} style={{ color: "#10b981" }} />
                  <div className="section-title" style={{ color: "var(--text-primary)" }}>
                    {isAr ? "خطة المعالجة ذات الأولوية (أوامر فورية)" : isFr ? "Feuille de Route Priorisée (Commandes Immédiates)" : "Prioritized Remediation Roadmap (Actionable Commands)"}
                  </div>
                </div>
                <div style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Sparkles size={14} style={{ color: result.remediation_source === "ai" ? "#10b981" : "#38bdf8" }} />
                  <span>
                    {result.remediation_source === "ai"
                      ? (isAr ? "توليد ذكي عبر Qwen 2.5 Coder" : isFr ? "Généré par l'IA Souveraine Qwen 2.5 Coder" : "Generated by Sovereign AI Qwen 2.5 Coder")
                      : (isAr ? "خطة مستهدفة عبر محرك قواعد ANCS" : isFr ? "Feuille de route ciblée (Moteur de Règles ANCS)" : "Targeted Roadmap (ANCS Rule Engine)")}
                  </span>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginTop: "14px" }}>
                {result.remediation_roadmap.map((step) => {
                  const isCopied = copiedStep === step.step_number;
                  return (
                    <div
                      key={step.step_number}
                      style={{
                        border: "1px solid var(--border-primary)",
                        backgroundColor: "var(--bg-secondary)",
                        padding: "16px 20px",
                        borderRadius: "var(--radius-sm)",
                        borderLeft: step.severity === "critical" ? "4px solid #ef4444" : step.severity === "high" ? "4px solid #f97316" : "4px solid #3b82f6",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px", marginBottom: "8px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span
                            style={{
                              backgroundColor: "var(--border-primary)",
                              color: "var(--text-primary)",
                              fontWeight: 700,
                              fontSize: "11px",
                              padding: "2px 8px",
                              borderRadius: "12px",
                            }}
                          >
                            #{step.step_number}
                          </span>
                          <span style={{ fontWeight: 600, fontSize: "14px", color: "var(--text-primary)" }}>
                            {step.title}
                          </span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          {step.estimated_score_gain > 0 && (
                            <span
                              style={{
                                backgroundColor: "rgba(16, 185, 129, 0.12)",
                                color: "#10b981",
                                border: "1px solid rgba(16, 185, 129, 0.3)",
                                fontSize: "11px",
                                fontWeight: 600,
                                padding: "2px 8px",
                                borderRadius: "4px",
                              }}
                            >
                              +{step.estimated_score_gain} pts {isAr ? "مكتسبة" : isFr ? "estimés" : "gain"}
                            </span>
                          )}
                          <span className={`severity-tag ${step.severity}`}>
                            {getSeverityLabel(step.severity)}
                          </span>
                        </div>
                      </div>

                      <div style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "12px", lineHeight: "1.5" }}>
                        {step.description}
                      </div>

                      {step.commands && (
                        <div
                          style={{
                            position: "relative",
                            backgroundColor: "#090d16",
                            border: "1px solid rgba(255, 255, 255, 0.08)",
                            borderRadius: "6px",
                            padding: "12px 14px",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                            <span style={{ fontSize: "10px", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                              Bash / Server Config
                            </span>
                            <button
                              type="button"
                              onClick={() => copyCommand(step.commands, step.step_number)}
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "4px",
                                background: isCopied ? "#10b981" : "rgba(255, 255, 255, 0.1)",
                                color: "#ffffff",
                                border: "none",
                                padding: "3px 8px",
                                borderRadius: "4px",
                                fontSize: "11px",
                                cursor: "pointer",
                                transition: "all 0.15s ease",
                              }}
                            >
                              {isCopied ? <Check size={12} /> : <Copy size={12} />}
                              <span>{isCopied ? (isAr ? "تم النسخ !" : isFr ? "Copié !" : "Copied!") : (isAr ? "نسخ" : isFr ? "Copier" : "Copy")}</span>
                            </button>
                          </div>
                          <pre
                            className="text-mono"
                            style={{
                              margin: 0,
                              color: "#38bdf8",
                              fontSize: "12px",
                              lineHeight: "1.6",
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-all",
                            }}
                          >
                            {step.commands}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Findings Table */}
          {result.findings && result.findings.length > 0 && (
            <div className="section mt-2xl">
              <div className="section-header">
                <div className="section-title">
                  {t("findings")} ({result.findings.length})
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {result.findings.slice(0, 30).map((f: any, i: number) => {
                  const titleStr = localize(f.title, locale);
                  const descStr = localize(f.description, locale);
                  const remStr = localize(f.remediation, locale);
                  const evidenceRaw = f.evidence;
                  const evidenceStr = evidenceRaw
                    ? (typeof evidenceRaw === "string" ? evidenceRaw : JSON.stringify(evidenceRaw, null, 2))
                    : "";

                  return (
                    <div
                      key={i}
                      style={{
                        border: "1px solid var(--border-primary)",
                        backgroundColor: "var(--bg-secondary)",
                        padding: "14px 18px",
                        borderRadius: "var(--radius-sm)",
                        transition: "border-color 0.15s ease",
                      }}
                    >
                      {/* Top Meta Line */}
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: "8px",
                          flexWrap: "wrap",
                          gap: "6px",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span className={`severity-tag ${f.severity}`}>
                            {getSeverityLabel(f.severity)}
                          </span>
                          <span
                            className="text-mono"
                            style={{
                              fontSize: "11px",
                              color: "var(--text-tertiary)",
                              letterSpacing: "0.5px",
                              textTransform: "uppercase",
                            }}
                          >
                            {String(f.category || "")} {f.owasp_category ? `• OWASP: ${f.owasp_category}` : ""}
                          </span>
                        </div>
                        {f.cvss_score && (
                          <span
                            className="text-mono"
                            style={{
                              fontSize: "11px",
                              fontWeight: 700,
                              color: "var(--color-critical)",
                              background: "rgba(239, 68, 68, 0.08)",
                              padding: "2px 6px",
                              borderRadius: "4px",
                            }}
                          >
                            CVSS {f.cvss_score}
                          </span>
                        )}
                      </div>

                      {/* Finding Title */}
                      <div
                        style={{
                          fontWeight: 600,
                          fontSize: "14px",
                          color: "var(--text-primary)",
                          marginBottom: "6px",
                        }}
                      >
                        {titleStr}
                      </div>

                      {/* Description */}
                      {descStr && (
                        <div
                          style={{
                            fontSize: "13px",
                            color: "var(--text-secondary)",
                            marginBottom: "8px",
                            lineHeight: 1.5,
                          }}
                        >
                          {descStr}
                        </div>
                      )}

                      {/* Command Center Technical Evidence Box */}
                      {evidenceStr && (
                        <div
                          dir="ltr"
                          style={{
                            backgroundColor: "var(--bg-tertiary)",
                            border: "1px solid var(--border-primary)",
                            borderInlineStart: "3px solid var(--color-accent)",
                            padding: "8px 12px",
                            borderRadius: "var(--radius-sm)",
                            fontFamily: "var(--font-mono, monospace)",
                            fontSize: "11px",
                            color: "var(--text-primary)",
                            margin: "8px 0",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            overflowX: "auto",
                            lineHeight: 1.5,
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "6px",
                              color: "var(--color-accent)",
                              fontSize: "10px",
                              fontWeight: 600,
                              letterSpacing: "0.5px",
                              textTransform: "uppercase",
                              marginBottom: "3px",
                              fontFamily: "var(--font-mono, monospace)",
                            }}
                          >
                            <Terminal size={12} />
                            <span>{isAr ? "الدليل التقني (EVIDENCE)" : isFr ? "PREUVE TECHNIQUE D'AUDIT" : "RAW TECHNICAL EVIDENCE"}</span>
                          </div>
                          <div style={{ color: "var(--text-secondary)", fontFamily: "monospace", fontSize: "11px" }}>
                            {evidenceStr}
                          </div>
                        </div>
                      )}

                      {/* Remediation Measure */}
                      {remStr && (
                        <div
                          style={{
                            fontSize: "12px",
                            color: "var(--color-success)",
                            marginTop: "6px",
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "6px",
                            lineHeight: 1.4,
                          }}
                        >
                          <span style={{ fontWeight: 700, fontSize: "11px", textTransform: "uppercase" }}>
                            {isAr ? "الإجراء التصحيحي:" : isFr ? "MESURE CORRECTIVE :" : "REMEDIATION:"}
                          </span>
                          <span>{remStr}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Bottom Action Buttons */}
          <div className="text-center mt-2xl" style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
            <ReportGenerator
              siteUrl={result.target.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]}
              reportData={convertScanResultToScanReport(result)}
              variant="button"
            />
            <button
              className="btn btn-secondary"
              onClick={resetScan}
              style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
            >
              <RefreshCw size={14} />
              <span>{t("scanAnother")}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
