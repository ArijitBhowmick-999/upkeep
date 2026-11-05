"use client";

import "./globals.css";
import React, { useState, useCallback, useEffect } from "react";
import {
  AlertCircle,
  CheckCircle2,
  Code,
  Copy,
  Database,
  Download,
  GitBranch,
  Info,
  Loader2,
  Play,
  ScrollText,
  Shield,
  X,
} from "lucide-react";

/* ================================================================== */
/*  Types                                                              */
/* ================================================================== */

interface Finding {
  ruleId: string;
  cwe: string;
  severity: "Critical" | "Medium" | "Low";
  line: number;
  message: string;
  remediation: string;
}

interface DependencyAudit {
  package: string;
  declaredVersion: string;
  latestVersion: string;
  status: "up-to-date" | "outdated" | "vulnerable";
  flag?: string;
}

interface AnalysisResult {
  _id?: string;
  moduleName: string;
  sourceCode?: string;
  metrics: {
    loc: number;
    cyclomaticComplexity: number;
    maintainabilityIndex: number;
    technicalDebtHours: number;
  };
  findings: Finding[];
  dependencyAudit: DependencyAudit[];
  refactoredCode: string;
}

interface AuditRecord {
  id: string;
  moduleName: string;
  sourceCode?: string;
  timestamp: Date;
  findingsCount: number;
  mi: number;
  debtHours: number;
  criticalCount: number;
  result: AnalysisResult;
}

type TabId = "findings" | "patch" | "deps" | "history";

/* ================================================================== */
/*  Sample Fixture Code                                                */
/* ================================================================== */

const SAMPLE_CODE = `const express = require('express');
const mysql = require('mysql');
const lodash = require('lodash');
const request = require('request');
const moment = require('moment');

var db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASS,
  database: 'legacy_app'
});

// DANGER: SQL injection via string concatenation
function getUserByName(name) {
  var query = "SELECT * FROM users WHERE name = '" + name + "'";
  return new Promise(function(resolve, reject) {
    db.query(query, function(err, results) {
      resolve(results);
    });
  });
}

// Dynamic code execution — arbitrary user input
function runUserFilter(filterCode, data) {
  var fn = new Function('data', filterCode);
  return fn(data);
}

function processOrder(orderId, callback) {
  db.query("SELECT * FROM orders WHERE id = " + orderId, function(err, rows) {
    var order = rows[0];
    if (order.status === 'pending') {
      var total = 0;
      for (var i = 0; i < order.items.length; i++) {
        total += order.items[i].price;
        if (order.items[i].discount) {
          total -= order.items[i].discount;
        }
      }
      if (total > 1000) {
        if (order.memberTier === 'gold') {
          total *= 0.9;
        } else if (order.memberTier === 'silver') {
          total *= 0.95;
        }
      }
      var tax = total * 0.08;
      callback(null, { total, tax, grandTotal: total + tax });
    } else {
      callback(new Error('Order not pending'));
    }
  });
}

// eval for config parsing
function loadConfig(rawJson) {
  var config = eval('(' + rawJson + ')');
  return config;
}

module.exports = { getUserByName, runUserFilter, processOrder, loadConfig };`;

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

function getRelativeTime(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  const now = new Date();
  const diffInSeconds = Math.max(1, Math.floor((now.getTime() - d.getTime()) / 1000));

  if (diffInSeconds < 45) return "just now";
  if (diffInSeconds < 90) return "1 min ago";
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes} mins ago`;
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours === 1) return "1 hr ago";
  if (diffInHours < 24) return `${diffInHours} hrs ago`;
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays === 1) return "yesterday";
  if (diffInDays < 30) return `${diffInDays} days ago`;
  return d.toLocaleDateString();
}

function toSARIF(r: AnalysisResult) {
  return {
    version: "2.1.0",
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Upkeep",
            version: "2.4.0",
            rules: r.findings.map((f) => ({
              id: f.ruleId,
              shortDescription: { text: f.message },
              help: { text: f.remediation },
              properties: { cwe: f.cwe },
            })),
          },
        },
        results: r.findings.map((f) => ({
          ruleId: f.ruleId,
          level:
            f.severity === "Critical"
              ? "error"
              : f.severity === "Medium"
                ? "warning"
                : "note",
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: `${r.moduleName}.js` },
                region: { startLine: f.line },
              },
            },
          ],
        })),
      },
    ],
  };
}

function mapToAuditRecord(item: any): AuditRecord {
  const issues = Array.isArray(item.issues) ? item.issues : item.findings || [];
  const manifestAudits = Array.isArray(item.manifestAudits)
    ? item.manifestAudits
    : item.dependencyAudit || [];
  const debt =
    typeof item.technicalDebtHours === "string"
      ? parseFloat(item.technicalDebtHours) || 0
      : (item.metrics?.technicalDebtHours ?? item.debtHours ?? 0);
  const mi = item.maintainabilityIndex ?? item.metrics?.maintainabilityIndex ?? 100;
  const cc = item.cyclomaticComplexity ?? item.metrics?.cyclomaticComplexity ?? 1;
  const loc = item.loc ?? item.metrics?.loc ?? 0;
  const refCode = item.refactoredCode || "";
  const criticalCount = issues.filter((f: any) => f.severity === "Critical").length;

  return {
    id: item._id?.toString() || item.id || crypto.randomUUID(),
    moduleName: item.moduleName || "untitled-module",
    sourceCode: item.sourceCode,
    timestamp: item.createdAt ? new Date(item.createdAt) : new Date(),
    findingsCount: item.issuesCount ?? issues.length,
    mi,
    debtHours: debt,
    criticalCount,
    result: {
      _id: item._id?.toString(),
      moduleName: item.moduleName || "untitled-module",
      sourceCode: item.sourceCode,
      metrics: {
        loc,
        cyclomaticComplexity: cc,
        maintainabilityIndex: mi,
        technicalDebtHours: debt,
      },
      findings: issues,
      dependencyAudit: manifestAudits,
      refactoredCode: refCode,
    },
  };
}

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export default function Home() {
  const [moduleName, setModuleName] = useState("legacy-core-service");
  const [sourceCode, setSourceCode] = useState(SAMPLE_CODE);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("findings");
  const [auditHistory, setAuditHistory] = useState<AuditRecord[]>([]);
  const [showArchitectureModal, setShowArchitectureModal] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);

  // Fetch past audits on mount
  useEffect(() => {
    async function loadPastAudits() {
      try {
        const res = await fetch("/api/analyze");
        if (!res.ok) return;
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
          setAuditHistory(data.map(mapToAuditRecord));
        }
      } catch (err) {
        console.warn("Could not load past audits:", err);
      }
    }
    loadPastAudits();
  }, []);

  const handleInsertSample = useCallback(() => {
    setSourceCode(SAMPLE_CODE);
    setModuleName("legacy-core-service");
    setError(null);
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!sourceCode.trim()) {
      setError("Please input source code before running analysis.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sourceCode, moduleName }),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(errBody?.error || `HTTP ${res.status}`);
      }
      const data: AnalysisResult = await res.json();
      setResult(data);
      setActiveTab("findings");

      const newRecord = mapToAuditRecord({
        _id: data._id,
        moduleName: data.moduleName,
        sourceCode,
        loc: data.metrics.loc,
        cyclomaticComplexity: data.metrics.cyclomaticComplexity,
        maintainabilityIndex: data.metrics.maintainabilityIndex,
        technicalDebtHours: String(data.metrics.technicalDebtHours),
        issuesCount: data.findings.length,
        issues: data.findings,
        manifestAudits: data.dependencyAudit,
        refactoredCode: data.refactoredCode,
        createdAt: new Date(),
      });
      setAuditHistory((prev) => [
        newRecord,
        ...prev.filter((r) => r.id !== newRecord.id),
      ].slice(0, 10));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Analysis request failed.");
    } finally {
      setLoading(false);
    }
  }, [sourceCode, moduleName]);

  const handleExportSARIF = useCallback(() => {
    if (!result) return;
    const data = toSARIF(result);
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `upkeep-${result.moduleName}.sarif.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [result]);

  const loadFromHistory = useCallback((record: AuditRecord) => {
    setResult(record.result);
    setModuleName(record.moduleName);
    if (record.sourceCode) {
      setSourceCode(record.sourceCode);
    }
    setActiveTab("findings");
  }, []);

  const handleCopyPatch = useCallback(() => {
    if (!result?.refactoredCode) return;
    navigator.clipboard.writeText(result.refactoredCode);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  }, [result]);

  const lineCount = sourceCode.split("\n").length;
  const refactoredLineCount = result
    ? result.refactoredCode.split("\n").length
    : 0;

  return (
    <div className="min-h-screen bg-gray-50 text-slate-900 flex flex-col font-sans">
      {/* ================================================================ */}
      {/*  Top Navigation Bar (Linear / GitHub Light Theme Style)          */}
      {/* ================================================================ */}
      <header className="border-b border-gray-200 bg-white sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          {/* Left: Clean Brand & Subtle Badge */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-slate-900 flex items-center justify-center text-white">
                <Shield className="w-3.5 h-3.5" />
              </div>
              <span className="font-bold text-sm text-slate-900 tracking-tight">
                Upkeep
              </span>
            </div>
            <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
              DevSecOps Static Telemetry
            </span>
          </div>

          {/* Right: Clean Gray Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowArchitectureModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 shadow-xs transition-colors"
            >
              <Info className="w-3.5 h-3.5 text-gray-500" />
              Project Architecture
            </button>
            <button
              onClick={handleExportSARIF}
              disabled={!result}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed shadow-xs transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-gray-500" />
              Export SARIF
            </button>
          </div>
        </div>
      </header>

      {/* ================================================================ */}
      {/*  Main Container                                                  */}
      {/* ================================================================ */}
      <main className="max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 flex-1 flex flex-col gap-6">
        {/* ============================================================== */}
        {/*  Summary Metric Cards (Clean, Pure White & Modern)             */}
        {/* ============================================================== */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Maintainability Score */}
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="text-xs font-medium text-slate-500 mb-1">
              Maintainability Score
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight">
                {result ? `${result.metrics.maintainabilityIndex}/100` : "—"}
              </span>
              {result && (
                <span
                  className={`text-[11px] font-medium px-2 py-0.5 rounded-full border ${
                    result.metrics.maintainabilityIndex >= 70
                      ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                      : result.metrics.maintainabilityIndex >= 45
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-rose-50 text-rose-700 border-rose-200"
                  }`}
                >
                  {result.metrics.maintainabilityIndex >= 70
                    ? "Good"
                    : result.metrics.maintainabilityIndex >= 45
                      ? "Moderate"
                      : "Critical"}
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Halstead logarithmic volume index
            </div>
          </div>

          {/* Technical Debt */}
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="text-xs font-medium text-slate-500 mb-1">
              Technical Debt
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold text-slate-900 tracking-tight">
                {result ? `${result.metrics.technicalDebtHours} hrs` : "—"}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Estimated remediation effort
            </div>
          </div>

          {/* Cyclomatic Complexity */}
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="text-xs font-medium text-slate-500 mb-1">
              Cyclomatic Complexity
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-slate-900 tracking-tight">
                {result ? result.metrics.cyclomaticComplexity : "—"}
              </span>
              {result && (
                <span className="text-xs text-slate-500 font-medium">
                  {result.metrics.cyclomaticComplexity <= 10
                    ? "Low risk"
                    : result.metrics.cyclomaticComplexity <= 20
                      ? "Moderate"
                      : "High risk"}
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              McCabe independent branch paths
            </div>
          </div>

          {/* Lines of Code */}
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="text-xs font-medium text-slate-500 mb-1">
              Lines of Code
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold text-slate-900 tracking-tight">
                {result ? result.metrics.loc : lineCount}
              </span>
              <span className="text-xs text-slate-500">lines</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Non-comment physical lines
            </div>
          </div>
        </section>

        {/* ============================================================== */}
        {/*  Two-Column Workspace                                          */}
        {/* ============================================================== */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* ============================================================ */}
          {/*  Left Column: Input & Sleek Dark Editor Box                  */}
          {/* ============================================================ */}
          <section className="lg:col-span-6 flex flex-col gap-3">
            {/* Integrated Sleek Service Identifier */}
            <div className="bg-white border border-gray-200 rounded-lg px-3.5 py-2 flex items-center justify-between gap-3 shadow-xs">
              <div className="flex items-center gap-2 min-w-0 flex-1">
                <GitBranch className="w-4 h-4 text-slate-500 shrink-0" />
                <span className="text-xs text-slate-500 font-medium shrink-0">
                  Target Service:
                </span>
                <input
                  type="text"
                  value={moduleName}
                  onChange={(e) => setModuleName(e.target.value)}
                  placeholder="e.g. billing-order-service"
                  className="bg-transparent border-0 px-1 py-0.5 text-xs text-slate-900 font-mono focus:outline-none placeholder-slate-400 min-w-0 flex-1 truncate"
                />
              </div>
              <span className="text-[11px] text-slate-500 shrink-0 font-mono hidden sm:inline">
                Node.js / JS
              </span>
            </div>

            {/* Editor Card with Clean Header Controls */}
            <div className="bg-white border border-gray-200 rounded-lg overflow-hidden flex flex-col shadow-xs">
              {/* Header with Title, Line Count, and Inline Controls */}
              <div className="px-3.5 py-2.5 border-b border-gray-200 bg-white flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-900">
                    Source Code
                  </span>
                  <span className="text-gray-300">·</span>
                  <span className="text-xs text-slate-500 font-mono">
                    {lineCount} lines
                  </span>
                </div>

                {/* Inline Header Buttons: Secondary Outline + Solid Blue Primary */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleInsertSample}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 transition-colors shadow-xs"
                  >
                    <ScrollText className="w-3.5 h-3.5 text-gray-500" />
                    Load Sample Fixture
                  </button>
                  <button
                    onClick={handleAnalyze}
                    disabled={loading}
                    className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-xs"
                  >
                    {loading ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Play className="w-3 h-3 fill-current" />
                    )}
                    {loading ? "Analyzing..." : "Run Analysis"}
                  </button>
                </div>
              </div>

              {/* Sleek Dark Slate Editor Box for clear code readability */}
              <div className="relative bg-slate-900 flex h-[500px] overflow-hidden rounded-b-md">
                {/* Gutter with line numbers */}
                <div
                  className="w-10 py-3 text-right pr-2 text-xs text-slate-500 select-none pointer-events-none font-mono border-r border-slate-800 bg-slate-950/60 overflow-hidden"
                  aria-hidden
                >
                  {Array.from({ length: lineCount }, (_, i) => (
                    <div key={i} className="leading-6 h-6">
                      {i + 1}
                    </div>
                  ))}
                </div>

                {/* Textarea */}
                <textarea
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value)}
                  spellCheck={false}
                  placeholder="Paste JavaScript source code here..."
                  className="code-editor flex-1 bg-transparent text-xs sm:text-sm text-slate-100 font-mono px-3 py-3 resize-none h-full overflow-y-auto focus:outline-none placeholder-slate-500"
                />
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-md bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </section>

          {/* ============================================================ */}
          {/*  Right Column: 4-Tab Panel with Telemetry & History          */}
          {/* ============================================================ */}
          <section className="lg:col-span-6 flex flex-col gap-3">
            <div className="bg-white border border-gray-200 rounded-lg overflow-hidden flex flex-col shadow-xs min-h-[560px]">
              {/* Clean Tab Navigation Header */}
              <div className="border-b border-gray-200 flex items-center px-2 bg-white overflow-x-auto">
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                    activeTab === "findings"
                      ? "border-blue-600 text-blue-600 font-semibold"
                      : "border-transparent text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Issues &amp; Findings
                  {result && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-700">
                      {result.findings.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("patch")}
                  className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                    activeTab === "patch"
                      ? "border-blue-600 text-blue-600 font-semibold"
                      : "border-transparent text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Refactored Code
                </button>
                <button
                  onClick={() => setActiveTab("deps")}
                  className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                    activeTab === "deps"
                      ? "border-blue-600 text-blue-600 font-semibold"
                      : "border-transparent text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Dependencies
                  {result && (
                    <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-700">
                      {result.dependencyAudit.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("history")}
                  className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                    activeTab === "history"
                      ? "border-blue-600 text-blue-600 font-semibold"
                      : "border-transparent text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Audit History
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-700">
                    {auditHistory.length}
                  </span>
                </button>
              </div>

              {/* Loading State Overlay */}
              {loading && (
                <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
                  <Loader2 className="w-6 h-6 text-blue-600 animate-spin mb-3" />
                  <p className="text-xs text-slate-700 font-medium">
                    Running AST static inspection and generating remediation...
                  </p>
                </div>
              )}

              {/* Tab 1: Issues & Findings */}
              {!loading && activeTab === "findings" && (
                <div className="flex-1 overflow-y-auto max-h-[500px]">
                  {!result ? (
                    <div className="p-12 text-center text-xs text-slate-500">
                      <Code className="w-8 h-8 text-slate-400 mx-auto mb-2 opacity-60" />
                      <p className="font-semibold text-slate-800 mb-1">
                        No Analysis Results Yet
                      </p>
                      <p className="max-w-xs mx-auto mb-4 text-slate-500">
                        Click &quot;Run Analysis&quot; above to inspect the codebase for security hazards, debt, and regressions.
                      </p>
                      <button
                        onClick={handleAnalyze}
                        className="px-3.5 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors shadow-xs"
                      >
                        Analyze Code Now
                      </button>
                    </div>
                  ) : result.findings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500">
                      <CheckCircle2 className="w-6 h-6 text-emerald-600 mx-auto mb-2" />
                      <span className="text-slate-900 font-semibold block mb-0.5">
                        No issues detected
                      </span>
                      Code passed all static analysis security rules.
                    </div>
                  ) : (
                    <div className="divide-y divide-gray-100">
                      {result.findings.map((f, i) => (
                        <div key={i} className="p-4 hover:bg-gray-50/80 transition-colors">
                          <div className="flex items-start gap-3">
                            <span
                              className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border shrink-0 mt-0.5 ${
                                f.severity === "Critical"
                                  ? "bg-rose-50 text-rose-700 border-rose-200"
                                  : f.severity === "Medium"
                                    ? "bg-amber-50 text-amber-700 border-amber-200"
                                    : "bg-slate-100 text-slate-700 border-slate-200"
                              }`}
                            >
                              {f.severity}
                            </span>

                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-mono text-xs font-semibold text-slate-900">
                                  {f.ruleId}
                                </span>
                                {f.cwe !== "N/A" && (
                                  <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[10px] text-slate-700 font-mono">
                                    {f.cwe}
                                  </span>
                                )}
                                <span className="text-xs text-slate-400">·</span>
                                <span className="text-xs text-slate-500">
                                  Line {f.line}
                                </span>
                              </div>

                              <p className="text-xs text-slate-700 leading-relaxed mb-2">
                                {f.message}
                              </p>

                              <div className="bg-slate-50 border border-slate-200 rounded-md p-2.5 text-xs text-slate-600">
                                <span className="font-semibold text-slate-900 block mb-0.5">
                                  Suggested Remediation:
                                </span>
                                {f.remediation}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Refactored Code */}
              {!loading && activeTab === "patch" && (
                <div className="flex-1 flex flex-col">
                  {!result ? (
                    <div className="p-12 text-center text-xs text-slate-500">
                      Run analysis to synthesize clean, refactored ES6 code.
                    </div>
                  ) : (
                    <>
                      <div className="px-4 py-2 border-b border-gray-200 flex items-center justify-between bg-gray-50">
                        <span className="text-xs text-slate-600 font-mono">
                          {result.moduleName}.refactored.js ({refactoredLineCount} lines)
                        </span>
                        <button
                          onClick={handleCopyPatch}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 transition-colors shadow-xs"
                        >
                          <Copy className="w-3.5 h-3.5 text-gray-500" />
                          {copiedPatch ? "Copied" : "Copy Code"}
                        </button>
                      </div>

                      <div className="bg-slate-900 p-3 overflow-y-auto font-mono text-xs text-slate-100 leading-6 h-[460px]">
                        {result.refactoredCode.split("\n").map((line, idx) => {
                          const originalLines = (sourceCode || "").split("\n");
                          const isModified =
                            idx < originalLines.length && line !== originalLines[idx];
                          return (
                            <div
                              key={idx}
                              className={`flex ${
                                isModified
                                  ? "bg-emerald-950/70 text-emerald-300 font-medium"
                                  : ""
                              }`}
                            >
                              <span className="w-8 text-right pr-3 text-slate-500 select-none shrink-0">
                                {idx + 1}
                              </span>
                              <span className="whitespace-pre">{line || " "}</span>
                            </div>
                          );
                        })}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Tab 3: Dependencies */}
              {!loading && activeTab === "deps" && (
                <div className="flex-1 overflow-auto max-h-[500px]">
                  {!result ? (
                    <div className="p-12 text-center text-xs text-slate-500">
                      Run analysis to inspect declared dependencies and CVE advisories.
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="bg-gray-50 text-slate-500 border-b border-gray-200">
                        <tr>
                          <th className="px-4 py-2 font-medium">Package</th>
                          <th className="px-4 py-2 font-medium">Declared</th>
                          <th className="px-4 py-2 font-medium">Latest</th>
                          <th className="px-4 py-2 font-medium">Status</th>
                          <th className="px-4 py-2 font-medium">Notes</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100">
                        {result.dependencyAudit.map((dep, i) => (
                          <tr key={i} className="hover:bg-gray-50 transition-colors">
                            <td className="px-4 py-2.5 font-mono font-medium text-slate-900">
                              {dep.package}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-slate-600">
                              {dep.declaredVersion}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-slate-600">
                              {dep.latestVersion}
                            </td>
                            <td className="px-4 py-2.5">
                              <span
                                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                                  dep.status === "up-to-date"
                                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                    : dep.status === "outdated"
                                      ? "bg-amber-50 text-amber-700 border-amber-200"
                                      : "bg-rose-50 text-rose-700 border-rose-200"
                                }`}
                              >
                                {dep.status === "up-to-date"
                                  ? "Current"
                                  : dep.status === "outdated"
                                    ? "Outdated"
                                    : "Vulnerable"}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-slate-500">
                              {dep.flag || "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* Tab 4: Live MongoDB Audit History */}
              {!loading && activeTab === "history" && (
                <div className="flex-1 overflow-auto max-h-[500px]">
                  <div className="px-4 py-2.5 border-b border-gray-200 flex items-center justify-between bg-gray-50">
                    <span className="text-xs text-slate-700 flex items-center gap-1.5 font-medium">
                      <Database className="w-3.5 h-3.5 text-blue-600" />
                      MongoDB Atlas Audit Records ({auditHistory.length})
                    </span>
                    <span className="text-[11px] text-slate-500">
                      Click row to restore scan
                    </span>
                  </div>

                  {auditHistory.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500">
                      No previous audits found in the database. Run an analysis to persist scan history.
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="bg-gray-50 text-slate-500 border-b border-gray-200">
                        <tr>
                          <th className="px-4 py-2 font-medium">Service / Module</th>
                          <th className="px-4 py-2 font-medium">Maintainability</th>
                          <th className="px-4 py-2 font-medium">LOC</th>
                          <th className="px-4 py-2 font-medium">Timestamp</th>
                          <th className="px-4 py-2 font-medium text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100">
                        {auditHistory.map((rec) => (
                          <tr
                            key={rec.id}
                            onClick={() => loadFromHistory(rec)}
                            className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                          >
                            <td className="px-4 py-2.5 font-medium text-slate-900 font-mono">
                              {rec.moduleName}
                            </td>
                            <td className="px-4 py-2.5">
                              <span
                                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                                  rec.mi >= 70
                                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                                    : rec.mi >= 45
                                      ? "bg-amber-50 text-amber-700 border-amber-200"
                                      : "bg-rose-50 text-rose-700 border-rose-200"
                                }`}
                              >
                                MI {rec.mi}/100
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-slate-600 font-mono">
                              {rec.result.metrics.loc} lines
                            </td>
                            <td className="px-4 py-2.5 text-slate-500">
                              {getRelativeTime(rec.timestamp)}
                            </td>
                            <td className="px-4 py-2.5 text-right">
                              <span className="text-xs text-blue-600 group-hover:text-blue-700 font-medium">
                                Restore →
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          </section>
        </div>
      </main>

      {/* ================================================================ */}
      {/*  Project Architecture Modal                                      */}
      {/* ================================================================ */}
      {showArchitectureModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white border border-gray-200 rounded-xl max-w-xl w-full max-h-[85vh] overflow-y-auto shadow-2xl p-6 text-xs text-slate-600 leading-relaxed">
            <div className="flex items-center justify-between pb-3 border-b border-gray-200 mb-4">
              <h2 className="text-sm font-semibold text-slate-900">
                Project Architecture &amp; Methodology
              </h2>
              <button
                onClick={() => setShowArchitectureModal(false)}
                className="text-slate-400 hover:text-slate-700 p-1 rounded-md transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <h3 className="font-semibold text-slate-900 text-xs mb-1">
                  1. Problem Overview
                </h3>
                <p className="text-slate-600">
                  Legacy software systems accumulate silent technical debt: outdated dependencies with vulnerabilities, obscure branching complexity, and regression hazards when manual changes are made without automated verification.
                </p>
              </div>

              <div>
                <h3 className="font-semibold text-slate-900 text-xs mb-1">
                  2. Analysis Pipeline
                </h3>
                <p className="text-slate-600">
                  Upkeep uses deterministic static code inspection:
                </p>
                <ul className="list-disc list-inside text-slate-600 mt-1 space-y-0.5">
                  <li>Physical Lines of Code (LOC) calculation</li>
                  <li>McCabe Cyclomatic Complexity path counting</li>
                  <li>Halstead Maintainability Index (0–100 scale)</li>
                  <li>CWE detection (CWE-89 SQL injection, CWE-95 dynamic execution)</li>
                </ul>
              </div>

              <div>
                <h3 className="font-semibold text-slate-900 text-xs mb-1">
                  3. Safe Refactoring
                </h3>
                <p className="text-slate-600">
                  The engine automatically generates safe modern ES6 replacements: scoping <code className="bg-gray-100 text-slate-800 px-1 py-0.5 rounded border border-gray-200">var</code> to <code className="bg-gray-100 text-slate-800 px-1 py-0.5 rounded border border-gray-200">const/let</code>, replacing dangerous <code className="bg-gray-100 text-slate-800 px-1 py-0.5 rounded border border-gray-200">eval()</code> with safe JSON parsing, and parameterizing raw concatenated SQL queries.
                </p>
              </div>

              <div>
                <h3 className="font-semibold text-slate-900 text-xs mb-1">
                  4. Stack
                </h3>
                <p className="text-slate-600">
                  Next.js App Router (TypeScript), Tailwind CSS, Node.js analysis engine, and MongoDB Atlas persistence via Mongoose.
                </p>
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-gray-200 flex justify-end">
              <button
                onClick={() => setShowArchitectureModal(false)}
                className="px-3.5 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 transition-colors shadow-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
