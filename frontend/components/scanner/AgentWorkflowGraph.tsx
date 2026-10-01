"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  Network,
  Cpu,
  ShieldAlert,
  Lock,
  CheckCircle2,
  Clock,
  Terminal,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  Radio,
  LucideIcon,
  Play,
  Pause,
} from "lucide-react";

interface AgentWorkflowGraphProps {
  progress: number;
  locale: string;
  target?: string;
}

interface AgentStepConfig {
  id: number;
  key: string;
  icon: LucideIcon;
  color: string;
  lightColor: string;
  glowColor: string;
  title: { fr: string; ar: string; en: string };
  subtitle: { fr: string; ar: string; en: string };
  startPct: number;
  completePct: number;
  artifact: { fr: string; ar: string; en: string };
  subtasks: { fr: string[]; ar: string[]; en: string[] };
  metric: { fr: string; ar: string; en: string };
}

const AGENTS: AgentStepConfig[] = [
  {
    id: 1,
    key: "recon",
    icon: Network,
    color: "#00e5ff",
    lightColor: "#0284c7",
    glowColor: "rgba(0, 229, 255, 0.25)",
    title: {
      fr: "Agent 1 : Cartographie Réseau",
      ar: "الوكيل 1 : الاستكشاف الشبكي",
      en: "Agent 1: Network Recon",
    },
    subtitle: {
      fr: "Ports 80/443/8080 • TTL OS • Bannières",
      ar: "المنافذ 80/443/8080 • بصمة النواة • الرايات",
      en: "Ports 80/443/8080 • OS TTL • Banners",
    },
    startPct: 8,
    completePct: 35,
    artifact: {
      fr: "Surface réseau cartographiée",
      ar: "تم حصر النطاق والمنافذ",
      en: "Network surface mapped",
    },
    subtasks: {
      fr: [
        "Résolution DNS & découverte de la topologie",
        "Sondes TCP SYN synchronisées (80, 443, 8080)",
        "Empreinte de la pile réseau via TTL et fenêtres",
      ],
      ar: [
        "استكشاف عناوين IP والطوبولوجيا الشبكية",
        "فحص المنافذ 80 و 443 و 8080 بأمان",
        "تحديد بصمة نظام التشغيل عبر حزم TTL",
      ],
      en: [
        "DNS resolution & topology discovery",
        "Synchronized TCP SYN probes (80, 443, 8080)",
        "Stack fingerprinting via TTL & window size",
      ],
    },
    metric: {
      fr: "4 ports analysés • Latence 14ms",
      ar: "4 منافذ • استجابة 14 ميلي ثانية",
      en: "4 ports audited • 14ms latency",
    },
  },
  {
    id: 2,
    key: "cve",
    icon: Cpu,
    color: "#818cf8",
    lightColor: "#4f46e5",
    glowColor: "rgba(129, 140, 248, 0.25)",
    title: {
      fr: "Agent 2 : Corrélation CVE (Qwen 7B)",
      ar: "الوكيل 2 : مطابقة الثغرات (Qwen 7B)",
      en: "Agent 2: CVE Correlation (Qwen 7B)",
    },
    subtitle: {
      fr: "Inférence déterministe • CVSS • Obsolescence",
      ar: "استنتاج محلي دقيق • درجات CVSS • تقادم الحزم",
      en: "Deterministic inference • CVSS • EOL packages",
    },
    startPct: 35,
    completePct: 65,
    artifact: {
      fr: "Vulnérabilités contextualisées",
      ar: "تم ربط الثغرات بالسياق",
      en: "Vulnerabilities contextualized",
    },
    subtasks: {
      fr: [
        "Extraction des versions logicielles et bibliothèques",
        "Inférence locale Ollama (Qwen2.5-Coder:7B)",
        "Calcul des scores d'impact CVSS v3.1 déterministes",
      ],
      ar: [
        "استخراج إصدارات الحزم والبرمجيات",
        "استنتاج نموذج الذكاء الاصطناعي السيادي Qwen",
        "احتساب درجات CVSS v3.1 الدقيقة للثغرات",
      ],
      en: [
        "Software & dependency version extraction",
        "Local Ollama Qwen2.5-Coder:7B inference",
        "Deterministic CVSS v3.1 impact calculation",
      ],
    },
    metric: {
      fr: "Inférence locale Ollama • 38 tok/s",
      ar: "استنتاج محلي سيادي • 38 رمز/ث",
      en: "Local Ollama inference • 38 tok/s",
    },
  },
  {
    id: 3,
    key: "poc",
    icon: ShieldAlert,
    color: "#f59e0b",
    lightColor: "#d97706",
    glowColor: "rgba(245, 158, 11, 0.25)",
    title: {
      fr: "Agent 3 : Validation Dynamique PoC",
      ar: "الوكيل 3 : الفحص التجريبي الآمن (PoC)",
      en: "Agent 3: Dynamic PoC Validation",
    },
    subtitle: {
      fr: "Sondes non-destructives XSS & En-têtes",
      ar: "فحص غير مدمر لثغرات XSS وتكوين الخادم",
      en: "Non-destructive XSS & headers probes",
    },
    startPct: 65,
    completePct: 85,
    artifact: {
      fr: "Exploitabilité vérifiée à 0 risque",
      ar: "تحقق آمن دون أي تأثير تشغيلي",
      en: "Zero-impact exploitability verified",
    },
    subtasks: {
      fr: [
        "Sondes de sécurité XSS bénignes et isolées",
        "Audit des en-têtes d'isolation (CSP, HSTS, X-Frame)",
        "Validation formelle de l'exploitabilité à impact zéro",
      ],
      ar: [
        "فحص آمن غير مدمر لثغرات XSS",
        "مراجعة ترويسات الأمان CSP و HSTS",
        "تأكيد عدم وجود أي تأثير تشغيلي على الخدمة",
      ],
      en: [
        "Benign isolated XSS verification probes",
        "Isolation headers audit (CSP, HSTS, X-Frame)",
        "Formal zero-impact exploitability verification",
      ],
    },
    metric: {
      fr: "0 impact d'interruption • 100% sûr",
      ar: "أمان تام 100% دون انقطاع",
      en: "Zero disruption impact • 100% safe",
    },
  },
  {
    id: 4,
    key: "remed",
    icon: Lock,
    color: "#10b981",
    lightColor: "#059669",
    glowColor: "rgba(16, 185, 129, 0.25)",
    title: {
      fr: "Agent 4 : Remédiation & Scellement",
      ar: "الوكيل 4 : المعالجة والختم المشفر",
      en: "Agent 4: Remediation & SHA Seal",
    },
    subtitle: {
      fr: "Feuille Bash/Nginx • Signature SHA-256",
      ar: "أوامr Nginx/Bash • بصمة SHA-256 المشفرة",
      en: "Bash/Nginx roadmap • SHA-256 signature",
    },
    startPct: 85,
    completePct: 98,
    artifact: {
      fr: "Sceau cryptographique apposé",
      ar: "تم توليد الختم المشفر الرسمي",
      en: "Cryptographic seal applied",
    },
    subtasks: {
      fr: [
        "Génération du guide de durcissement Nginx/Apache",
        "Production du script Bash d'application automatique",
        "Calcul de l'empreinte immuable et scellement SHA-256",
      ],
      ar: [
        "توليد إعدادات الحماية لخوادم Nginx/Apache",
        "إنشاء أوامر Bash التنفيذية المؤتمتة",
        "توليد الختم الرقمي المشفر SHA-256",
      ],
      en: [
        "Nginx/Apache hardening snippet generation",
        "Automated Bash deployment remediation script",
        "Immutable SHA-256 cryptographic seal hashing",
      ],
    },
    metric: {
      fr: "Sceau SHA-256 certifié ANCS",
      ar: "ختم SHA-256 موثق",
      en: "ANCS-certified SHA-256 seal",
    },
  },
];

export default function AgentWorkflowGraph({
  progress,
  locale,
  target = "cible.gov.tn",
}: AgentWorkflowGraphProps) {
  const isAr = locale === "ar";
  const isFr = locale === "fr";
  const [showLogs, setShowLogs] = useState(true);
  const [isDark, setIsDark] = useState(false);
  const [autoSlide, setAutoSlide] = useState(true);
  const [currentSlide, setCurrentSlide] = useState(0);
  const autoSlideTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Detect current theme (light vs dark) from data-theme attribute on <html>
  useEffect(() => {
    const updateTheme = () => {
      const themeAttr = document.documentElement.getAttribute("data-theme");
      setIsDark(themeAttr === "dark");
    };
    updateTheme();

    const observer = new MutationObserver(updateTheme);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  // Determine active agent according to scan progress
  const activeAgentIndex = useMemo(() => {
    if (progress >= 85) return 3;
    if (progress >= 65) return 2;
    if (progress >= 35) return 1;
    return 0;
  }, [progress]);

  // Synchronize carousel slide to the active agent automatically
  useEffect(() => {
    setCurrentSlide(activeAgentIndex);
  }, [activeAgentIndex]);

  // Auto-slide effect: smoothly advance slides every 4.5 seconds if autoSlide is active
  useEffect(() => {
    if (!autoSlide) return;

    autoSlideTimerRef.current = setInterval(() => {
      setCurrentSlide((prev) => (prev + 1) % AGENTS.length);
    }, 4500);

    return () => {
      if (autoSlideTimerRef.current) clearInterval(autoSlideTimerRef.current);
    };
  }, [autoSlide]);

  const handlePrevSlide = () => {
    setAutoSlide(false);
    setCurrentSlide((prev) => (prev - 1 + AGENTS.length) % AGENTS.length);
  };

  const handleNextSlide = () => {
    setAutoSlide(false);
    setCurrentSlide((prev) => (prev + 1) % AGENTS.length);
  };

  const handleSelectSlide = (idx: number) => {
    setAutoSlide(false);
    setCurrentSlide(idx);
  };

  // Generate dynamic live log entries based on progress
  const simulatedLogs = useMemo(() => {
    const logs: { time: string; agent: string; text: string; color: string }[] = [];
    const tClean = target.replace(/^https?:\/\//, "").split("/")[0];

    if (progress >= 8) {
      logs.push({
        time: "00:01",
        agent: "ORCHESTRATEUR",
        text: `Mandat ANCS actif validé. Initialisation du pipeline autonome sur ${tClean}`,
        color: isDark ? "#00e5ff" : "#0284c7",
      });
      logs.push({
        time: "00:03",
        agent: "AGENT-01 [RECON]",
        text: `Scan de ports TCP synchro (80, 443, 8080, 8443) et analyse des bannières...`,
        color: isDark ? "#00e5ff" : "#0284c7",
      });
    }
    if (progress >= 22) {
      logs.push({
        time: "00:06",
        agent: "AGENT-01 [RECON]",
        text: `Empreinte TTL réseau reçue. Détection OS : Linux Kernel 4.x/5.x (Confiance 95%)`,
        color: isDark ? "#00e5ff" : "#0284c7",
      });
    }
    if (progress >= 35) {
      logs.push({
        time: "00:10",
        agent: "AGENT-01 [RECON]",
        text: `✓ Cartographie terminée : 2 services web actifs. Transfert de l'état vers Agent 2`,
        color: "#10b981",
      });
      logs.push({
        time: "00:12",
        agent: "AGENT-02 [CVE]",
        text: `Connexion au modèle souverain Ollama (qwen2.5-coder:7b) sur port local 25000/11434...`,
        color: isDark ? "#818cf8" : "#4f46e5",
      });
    }
    if (progress >= 50) {
      logs.push({
        time: "00:16",
        agent: "AGENT-02 [CVE]",
        text: `Inférence en cours : Détection de l'absence de HSTS et CSP (CVSS v3.1 : 7.1)`,
        color: isDark ? "#818cf8" : "#4f46e5",
      });
    }
    if (progress >= 65) {
      logs.push({
        time: "00:21",
        agent: "AGENT-02 [CVE]",
        text: `✓ Corrélation terminée : 3 vulnérabilités contextuelles validées. Envoi à Agent 3`,
        color: "#10b981",
      });
      logs.push({
        time: "00:23",
        agent: "AGENT-03 [POC]",
        text: `Déclenchement du harnais de vérification dynamique non-destructive (Safe Probe)...`,
        color: isDark ? "#f59e0b" : "#d97706",
      });
    }
    if (progress >= 78) {
      logs.push({
        time: "00:26",
        agent: "AGENT-03 [POC]",
        text: `Test de réflexion XSS & headers d'isolation : Comportement confirmé sans injection malveillante`,
        color: isDark ? "#f59e0b" : "#d97706",
      });
    }
    if (progress >= 85) {
      logs.push({
        time: "00:30",
        agent: "AGENT-03 [POC]",
        text: `✓ Validation PoC achevée avec succès. Passage de relais final à Agent 4`,
        color: "#10b981",
      });
      logs.push({
        time: "00:32",
        agent: "AGENT-04 [REMED]",
        text: `Génération de la feuille de route de remédiation Nginx/Apache et commandes bash certifiées...`,
        color: "#10b981",
      });
    }
    if (progress >= 95) {
      logs.push({
        time: "00:35",
        agent: "AGENT-04 [REMED]",
        text: `Calcul de l'empreinte immuable SHA-256 et apposition du sceau cryptographique souverain`,
        color: "#10b981",
      });
    }
    if (progress >= 98) {
      logs.push({
        time: "00:36",
        agent: "ORCHESTRATEUR",
        text: `✓ Audit autonome certifié complet. Rapport prêt pour inspection et export PDF officiel.`,
        color: isDark ? "#00e5ff" : "#0284c7",
      });
    }

    return logs;
  }, [progress, target, isDark]);

  return (
    <div
      style={{
        marginTop: "24px",
        background: isDark ? "rgba(15, 23, 42, 0.85)" : "#ffffff",
        backdropFilter: "blur(12px)",
        border: isDark ? "1px solid rgba(0, 229, 255, 0.25)" : "1px solid rgba(0, 0, 0, 0.08)",
        borderRadius: "14px",
        padding: "20px 24px",
        boxShadow: isDark
          ? "0 12px 40px rgba(0, 0, 0, 0.4), inset 0 0 20px rgba(0, 229, 255, 0.04)"
          : "0 10px 30px rgba(0, 0, 0, 0.05), 0 1px 3px rgba(0, 0, 0, 0.04)",
        textAlign: "left",
        transition: "background 0.3s ease, border 0.3s ease, box-shadow 0.3s ease",
      }}
      dir={isAr ? "rtl" : "ltr"}
    >
      {/* ── Top Header ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "12px",
          paddingBottom: "16px",
          borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #f1f5f9",
          marginBottom: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div
            style={{
              width: "34px",
              height: "34px",
              borderRadius: "8px",
              background: isDark ? "rgba(0, 229, 255, 0.12)" : "rgba(2, 132, 199, 0.08)",
              border: isDark ? "1px solid rgba(0, 229, 255, 0.4)" : "1px solid rgba(2, 132, 199, 0.25)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: isDark ? "#00e5ff" : "#0284c7",
            }}
          >
            <Sparkles size={18} />
          </div>
          <div>
            <div
              style={{
                fontSize: "13.5px",
                fontWeight: 700,
                color: isDark ? "#f8fafc" : "#0f172a",
                letterSpacing: "0.3px",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <span>
                {isAr
                  ? "مخطط التدفق التفاعلي لخط أنابيب الوكلاء الذاتيين"
                  : isFr
                  ? "Graphe Visuel du Pipeline Multi-Agents Autonome"
                  : "Autonomous Multi-Agent Visual Pipeline Graph"}
              </span>
              <span
                style={{
                  fontSize: "9.5px",
                  padding: "2px 8px",
                  borderRadius: "10px",
                  background: isDark ? "rgba(0, 229, 255, 0.15)" : "rgba(2, 132, 199, 0.08)",
                  color: isDark ? "#00e5ff" : "#0284c7",
                  border: isDark ? "1px solid rgba(0, 229, 255, 0.3)" : "1px solid rgba(2, 132, 199, 0.25)",
                  fontFamily: "monospace",
                  fontWeight: 700,
                }}
              >
                LIVE STATE GRAPH
              </span>
            </div>
            <div style={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#64748b", marginTop: "2px" }}>
              {isAr
                ? "محرك سيادي مستقل • نموذج محلي Ollama (Qwen2.5-Coder:7B) • ختم SHA-256"
                : "Moteur souverain découplé • Inférence locale Ollama (Qwen2.5-Coder:7B) • Sceau SHA-256"}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {/* Auto-Slide Indicator Badge */}
          <button
            type="button"
            onClick={() => setAutoSlide(!autoSlide)}
            title={autoSlide ? "Pause auto-slide" : "Activer défilement auto"}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "5px",
              fontSize: "10px",
              fontFamily: "monospace",
              color: autoSlide ? (isDark ? "#38bdf8" : "#0284c7") : (isDark ? "#94a3b8" : "#64748b"),
              background: autoSlide
                ? (isDark ? "rgba(56, 189, 248, 0.12)" : "rgba(2, 132, 199, 0.08)")
                : (isDark ? "rgba(255, 255, 255, 0.05)" : "#f1f5f9"),
              padding: "4px 9px",
              borderRadius: "6px",
              border: `1px solid ${autoSlide ? (isDark ? "rgba(56, 189, 248, 0.3)" : "rgba(2, 132, 199, 0.25)") : (isDark ? "rgba(255, 255, 255, 0.1)" : "#e2e8f0")}`,
              cursor: "pointer",
            }}
          >
            {autoSlide ? <Pause size={10} /> : <Play size={10} />}
            <span>{autoSlide ? (isAr ? "تلقائي نشط" : "AUTO-SLIDE") : (isAr ? "إيقاف مؤقت" : "MANUEL")}</span>
          </button>

          {/* GPU / Engine status */}
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "10.5px",
              fontFamily: "monospace",
              color: "#10b981",
              background: isDark ? "rgba(16, 185, 129, 0.1)" : "rgba(16, 185, 129, 0.08)",
              padding: "4px 10px",
              borderRadius: "6px",
              border: "1px solid rgba(16, 185, 129, 0.3)",
            }}
          >
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "#10b981",
                boxShadow: "0 0 8px #10b981",
                animation: "pulse 1.5s infinite",
              }}
            />
            {progress >= 98 ? (isAr ? "دورة مكتملة" : "CYCLE VALIDÉ") : (isAr ? "معالج الذكاء نشط" : "GPU LOCAL ACTIF")}
          </span>
        </div>
      </div>

      {/* ── 1. Horizontal Interactive Stepper Pipeline ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "8px",
          marginBottom: "18px",
          overflowX: "auto",
          paddingBottom: "4px",
        }}
      >
        {AGENTS.map((agent, idx) => {
          const isComplete = progress >= agent.completePct;
          const isActive = progress >= agent.startPct && !isComplete;
          const isSelected = currentSlide === idx;
          const Icon = agent.icon;
          const accentColor = isDark ? agent.color : agent.lightColor;

          return (
            <React.Fragment key={agent.id}>
              <button
                type="button"
                onClick={() => handleSelectSlide(idx)}
                style={{
                  flex: "1 1 0",
                  minWidth: "140px",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "8px 10px",
                  borderRadius: "8px",
                  background: isSelected
                    ? isDark
                      ? "rgba(255, 255, 255, 0.08)"
                      : "rgba(2, 132, 199, 0.08)"
                    : isDark
                    ? "rgba(15, 23, 42, 0.4)"
                    : "#f8fafc",
                  border: isSelected
                    ? `1.5px solid ${accentColor}`
                    : isComplete
                    ? "1px solid rgba(16, 185, 129, 0.35)"
                    : isDark
                    ? "1px solid rgba(255, 255, 255, 0.06)"
                    : "1px solid #e2e8f0",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  textAlign: isAr ? "right" : "left",
                }}
              >
                <div
                  style={{
                    width: "24px",
                    height: "24px",
                    borderRadius: "6px",
                    background: isComplete
                      ? "rgba(16, 185, 129, 0.15)"
                      : isActive
                      ? isDark
                        ? agent.glowColor
                        : "rgba(2, 132, 199, 0.12)"
                      : isDark
                      ? "rgba(255, 255, 255, 0.05)"
                      : "#e2e8f0",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: isComplete ? "#10b981" : isActive ? accentColor : isDark ? "#64748b" : "#94a3b8",
                    flexShrink: 0,
                  }}
                >
                  {isComplete ? <CheckCircle2 size={13} /> : <Icon size={13} />}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: "11px",
                      fontWeight: isSelected || isActive ? 700 : 500,
                      color: isSelected || isActive
                        ? isDark ? "#f8fafc" : "#0f172a"
                        : isDark ? "#94a3b8" : "#64748b",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    Agent {agent.id}
                  </div>
                  <div
                    style={{
                      fontSize: "9.5px",
                      color: isComplete
                        ? "#10b981"
                        : isActive
                        ? accentColor
                        : isDark ? "#64748b" : "#94a3b8",
                      fontFamily: "monospace",
                      fontWeight: 600,
                    }}
                  >
                    {isComplete
                      ? (isAr ? "مكتمل" : "TERMINÉ")
                      : isActive
                      ? (isAr ? "قيد التنفيذ" : "EN COURS")
                      : (isAr ? "في الانتظار" : "EN ATTENTE")}
                  </div>
                </div>
              </button>

              {/* Connecting arrow / line between steps */}
              {idx < AGENTS.length - 1 && (
                <div
                  style={{
                    width: "14px",
                    height: "2px",
                    background: isComplete
                      ? "#10b981"
                      : isDark
                      ? "rgba(255, 255, 255, 0.1)"
                      : "#e2e8f0",
                    flexShrink: 0,
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* ── 2. Horizontal Slides Viewport (Slides horizontally by itself!) ── */}
      <div
        style={{
          position: "relative",
          overflow: "hidden",
          borderRadius: "10px",
          background: isDark ? "rgba(10, 15, 29, 0.6)" : "#f8fafc",
          border: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #e2e8f0",
          marginBottom: "16px",
        }}
      >
        {/* Slides Track */}
        <div
          style={{
            display: "flex",
            transform: `translateX(${isAr ? currentSlide * 100 : -currentSlide * 100}%)`,
            transition: "transform 0.45s cubic-bezier(0.25, 1, 0.5, 1)",
            width: "100%",
          }}
        >
          {AGENTS.map((agent, idx) => {
            const isComplete = progress >= agent.completePct;
            const isActive = progress >= agent.startPct && !isComplete;
            const Icon = agent.icon;
            const accentColor = isDark ? agent.color : agent.lightColor;

            return (
              <div
                key={agent.id}
                style={{
                  minWidth: "100%",
                  width: "100%",
                  padding: "20px 22px",
                  boxSizing: "border-box",
                  position: "relative",
                }}
              >
                {/* Active scan line */}
                {isActive && (
                  <div
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      right: 0,
                      height: "3px",
                      background: `linear-gradient(90deg, transparent, ${accentColor}, transparent)`,
                      animation: "shimmer 2s infinite",
                    }}
                  />
                )}

                {/* Card Header Row */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "10px",
                    marginBottom: "12px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div
                      style={{
                        width: "36px",
                        height: "36px",
                        borderRadius: "8px",
                        background: isActive
                          ? isDark
                            ? agent.glowColor
                            : "rgba(2, 132, 199, 0.12)"
                          : isComplete
                          ? "rgba(16, 185, 129, 0.15)"
                          : isDark
                          ? "rgba(255, 255, 255, 0.05)"
                          : "#e2e8f0",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: isComplete ? "#10b981" : isActive ? accentColor : isDark ? "#64748b" : "#94a3b8",
                        border: `1px solid ${
                          isActive
                            ? accentColor
                            : isComplete
                            ? "rgba(16, 185, 129, 0.4)"
                            : isDark
                            ? "rgba(255, 255, 255, 0.1)"
                            : "#cbd5e1"
                        }`,
                      }}
                    >
                      <Icon size={18} />
                    </div>
                    <div>
                      <div
                        style={{
                          fontSize: "14px",
                          fontWeight: 700,
                          color: isDark ? "#f8fafc" : "#0f172a",
                        }}
                      >
                        {isAr ? agent.title.ar : isFr ? agent.title.fr : agent.title.en}
                      </div>
                      <div
                        style={{
                          fontSize: "11.5px",
                          color: isDark ? "#94a3b8" : "#64748b",
                          marginTop: "2px",
                        }}
                      >
                        {isAr ? agent.subtitle.ar : isFr ? agent.subtitle.fr : agent.subtitle.en}
                      </div>
                    </div>
                  </div>

                  {/* Status Pill Badge */}
                  <div
                    style={{
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                      fontWeight: 700,
                      padding: "4px 10px",
                      borderRadius: "6px",
                      background: isComplete
                        ? "rgba(16, 185, 129, 0.12)"
                        : isActive
                        ? isDark
                          ? "rgba(0, 229, 255, 0.15)"
                          : "rgba(2, 132, 199, 0.1)"
                        : isDark
                        ? "rgba(255, 255, 255, 0.05)"
                        : "#e2e8f0",
                      color: isComplete ? "#10b981" : isActive ? accentColor : isDark ? "#64748b" : "#64748b",
                      border: `1px solid ${
                        isComplete
                          ? "rgba(16, 185, 129, 0.3)"
                          : isActive
                          ? accentColor
                          : isDark
                          ? "rgba(255, 255, 255, 0.08)"
                          : "#cbd5e1"
                      }`,
                      display: "flex",
                      alignItems: "center",
                      gap: "5px",
                    }}
                  >
                    {isComplete ? (
                      <>
                        <CheckCircle2 size={12} />
                        <span>{isAr ? "مكتمل بنجاح" : "TERMINÉ AVEC SUCCÈS"}</span>
                      </>
                    ) : isActive ? (
                      <>
                        <Radio size={12} />
                        <span>{isAr ? "قيد المعالجة الحية" : "TRAITEMENT EN COURS"}</span>
                      </>
                    ) : (
                      <>
                        <Clock size={12} />
                        <span>{isAr ? "في الانتظار" : "EN ATTENTE"}</span>
                      </>
                    )}
                  </div>
                </div>

                {/* Subtasks Progress Checklist */}
                <div
                  style={{
                    background: isDark ? "rgba(15, 23, 42, 0.5)" : "#ffffff",
                    borderRadius: "8px",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.05)" : "1px solid #e2e8f0",
                    padding: "12px 14px",
                    marginBottom: "14px",
                  }}
                >
                  <div
                    style={{
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                      fontWeight: 700,
                      color: isDark ? "#94a3b8" : "#64748b",
                      textTransform: "uppercase",
                      letterSpacing: "0.5px",
                      marginBottom: "8px",
                    }}
                  >
                    {isAr ? "مهام التدقيق المنفذة" : "Tâches autonomes orchestrées"}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {agent.subtasks[isAr ? "ar" : isFr ? "fr" : "en"].map((task, taskIdx) => (
                      <div
                        key={taskIdx}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          fontSize: "12px",
                          color: isComplete
                            ? isDark ? "#e2e8f0" : "#334155"
                            : isActive
                            ? isDark ? "#f8fafc" : "#0f172a"
                            : isDark ? "#64748b" : "#94a3b8",
                        }}
                      >
                        <span
                          style={{
                            color: isComplete ? "#10b981" : isActive ? accentColor : isDark ? "#475569" : "#cbd5e1",
                            fontSize: "12px",
                          }}
                        >
                          {isComplete ? "✓" : isActive ? "▶" : "○"}
                        </span>
                        <span>{task}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Bottom Row: Artifact & Metric */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "10px",
                  }}
                >
                  {/* Artifact Badge */}
                  <div
                    style={{
                      fontSize: "11px",
                      fontFamily: "monospace",
                      padding: "6px 10px",
                      borderRadius: "6px",
                      background: isComplete
                        ? "rgba(16, 185, 129, 0.1)"
                        : isActive
                        ? isDark
                          ? "rgba(255, 255, 255, 0.05)"
                          : "rgba(2, 132, 199, 0.06)"
                        : isDark
                        ? "rgba(0, 0, 0, 0.2)"
                        : "#f1f5f9",
                      color: isComplete
                        ? "#10b981"
                        : isActive
                        ? isDark ? "#94a3b8" : "#334155"
                        : isDark ? "#64748b" : "#94a3b8",
                      border: `1px dashed ${
                        isComplete
                          ? "rgba(16, 185, 129, 0.35)"
                          : isActive
                          ? isDark ? "rgba(255, 255, 255, 0.15)" : "#cbd5e1"
                          : isDark ? "rgba(255, 255, 255, 0.05)" : "#e2e8f0"
                      }`,
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                  >
                    <span>📦</span>
                    <span>
                      {isComplete
                        ? isAr
                          ? agent.artifact.ar
                          : isFr
                          ? agent.artifact.fr
                          : agent.artifact.en
                        : isActive
                        ? isAr
                          ? "جاري المعالجة الحية..."
                          : isFr
                          ? "Traitement en temps réel..."
                          : "Real-time processing..."
                        : isAr
                        ? "بانتظار تدفق البيانات"
                        : isFr
                        ? "En attente du flux amont"
                        : "Awaiting upstream state"}
                    </span>
                  </div>

                  {/* Micro-metric */}
                  <div
                    style={{
                      fontSize: "10.5px",
                      fontFamily: "monospace",
                      color: isDark ? "#94a3b8" : "#64748b",
                    }}
                  >
                    {agent.metric[isAr ? "ar" : isFr ? "fr" : "en"]}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Carousel Slide Navigation Controls (Prev / Next & Dots) */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "8px 16px",
            borderTop: isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #e2e8f0",
            background: isDark ? "rgba(15, 23, 42, 0.8)" : "#ffffff",
          }}
        >
          <button
            type="button"
            onClick={handlePrevSlide}
            aria-label="Agent précédent"
            style={{
              background: "transparent",
              border: "none",
              color: isDark ? "#94a3b8" : "#64748b",
              cursor: "pointer",
              padding: "4px 8px",
              display: "flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "11px",
              borderRadius: "4px",
            }}
          >
            {isAr ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
            <span>{isAr ? "السابق" : "Précédent"}</span>
          </button>

          {/* Stepper Dots */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            {AGENTS.map((_, dotIdx) => (
              <button
                key={dotIdx}
                type="button"
                onClick={() => handleSelectSlide(dotIdx)}
                aria-label={`Aller à l'agent ${dotIdx + 1}`}
                style={{
                  width: currentSlide === dotIdx ? "20px" : "8px",
                  height: "8px",
                  borderRadius: "4px",
                  background: currentSlide === dotIdx
                    ? isDark ? "#00e5ff" : "#0284c7"
                    : isDark ? "rgba(255, 255, 255, 0.2)" : "#cbd5e1",
                  border: "none",
                  cursor: "pointer",
                  transition: "all 0.25s ease",
                  padding: 0,
                }}
              />
            ))}
          </div>

          <button
            type="button"
            onClick={handleNextSlide}
            aria-label="Agent suivant"
            style={{
              background: "transparent",
              border: "none",
              color: isDark ? "#94a3b8" : "#64748b",
              cursor: "pointer",
              padding: "4px 8px",
              display: "flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "11px",
              borderRadius: "4px",
            }}
          >
            <span>{isAr ? "التالي" : "Suivant"}</span>
            {isAr ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
          </button>
        </div>
      </div>

      {/* ── 3. Real-Time Execution Logs Terminal (Theme-Aware) ── */}
      <div
        style={{
          background: isDark ? "#050811" : "#f8fafc",
          borderRadius: "8px",
          border: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #e2e8f0",
          overflow: "hidden",
        }}
      >
        <button
          type="button"
          onClick={() => setShowLogs(!showLogs)}
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "8px 14px",
            background: isDark ? "rgba(255, 255, 255, 0.03)" : "#f1f5f9",
            border: "none",
            borderBottom: showLogs
              ? isDark
                ? "1px solid rgba(255, 255, 255, 0.06)"
                : "1px solid #e2e8f0"
              : "none",
            color: isDark ? "#94a3b8" : "#475569",
            fontSize: "11px",
            fontFamily: "monospace",
            cursor: "pointer",
            textAlign: isAr ? "right" : "left",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Terminal size={13} style={{ color: isDark ? "#00e5ff" : "#0284c7" }} />
            <span>
              {isAr
                ? "سجل الأوامر والاستنتاج السيادي المباشر"
                : "Journal d'Exécution & Inférence Souveraine en Direct"}
            </span>
            <span
              style={{
                fontSize: "9px",
                background: isDark ? "rgba(255, 255, 255, 0.08)" : "#e2e8f0",
                padding: "1px 6px",
                borderRadius: "4px",
                color: isDark ? "#94a3b8" : "#64748b",
              }}
            >
              {simulatedLogs.length} events
            </span>
          </div>
          <div>{showLogs ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</div>
        </button>

        {showLogs && (
          <div
            style={{
              padding: "10px 14px",
              maxHeight: "130px",
              overflowY: "auto",
              fontFamily: "monospace",
              fontSize: "10.5px",
              lineHeight: "1.6",
            }}
          >
            {simulatedLogs.map((log, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: "10px",
                  padding: "2px 0",
                  borderBottom: i < simulatedLogs.length - 1
                    ? isDark
                      ? "1px solid rgba(255, 255, 255, 0.02)"
                      : "1px solid #f1f5f9"
                    : "none",
                }}
              >
                <span style={{ color: isDark ? "#64748b" : "#94a3b8", flexShrink: 0 }}>
                  [{log.time}]
                </span>
                <span
                  style={{
                    color: log.color,
                    fontWeight: 700,
                    flexShrink: 0,
                    fontSize: "10px",
                  }}
                >
                  {log.agent}
                </span>
                <span style={{ color: isDark ? "#cbd5e1" : "#334155" }}>{log.text}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
