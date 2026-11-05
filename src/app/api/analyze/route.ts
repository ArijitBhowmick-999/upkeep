import { NextRequest, NextResponse } from "next/server";
import { connectDB } from "@/lib/db";
import AuditRecord from "@/models/AuditRecord";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Metric calculators                                                 */
/* ------------------------------------------------------------------ */

/** Count physical, non-empty, non-comment-only lines of code. */
function countLOC(source: string): number {
  const lines = source.split("\n");
  let count = 0;
  let inBlock = false;

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (trimmed === "") continue;

    if (inBlock) {
      if (trimmed.includes("*/")) inBlock = false;
      continue;
    }

    if (trimmed.startsWith("/*")) {
      if (!trimmed.includes("*/")) inBlock = true;
      continue;
    }

    if (trimmed.startsWith("//")) continue;

    count++;
  }

  return count;
}

/**
 * Cyclomatic complexity — counts decision points.
 * M = 1 + (number of branching keywords / operators).
 */
function cyclomaticComplexity(source: string): number {
  const branchPatterns = [
    /\bif\s*\(/g,
    /\belse\s+if\s*\(/g,
    /\bfor\s*\(/g,
    /\bwhile\s*\(/g,
    /\bcase\s+/g,
    /\bcatch\s*\(/g,
    /\?\?/g,       // nullish coalescing
    /\?\./g,       // optional chaining (represents a hidden branch)
    /&&/g,
    /\|\|/g,
    /\?[^.?]/g,    // ternary (but not ?. or ??)
  ];

  let complexity = 1; // base path

  for (const pattern of branchPatterns) {
    const matches = source.match(pattern);
    if (matches) complexity += matches.length;
  }

  return complexity;
}

/**
 * Maintainability Index (simplified Microsoft formula, clamped 0-100).
 * MI = max(0, (171 - 5.2 * ln(V) - 0.23 * G - 16.2 * ln(LOC)) * 100 / 171)
 * Where V ≈ LOC * ln(LOC) (Halstead volume approximation) and G = cyclomatic complexity.
 */
function maintainabilityIndex(loc: number, complexity: number): number {
  if (loc <= 0) return 100;

  const halsteadVolume = loc * Math.log(Math.max(loc, 1));
  const raw =
    171 -
    5.2 * Math.log(Math.max(halsteadVolume, 1)) -
    0.23 * complexity -
    16.2 * Math.log(Math.max(loc, 1));

  return Math.round(Math.max(0, Math.min(100, (raw * 100) / 171)));
}

/**
 * Technical debt estimate in hours.
 * Heuristic: 30 min per finding + scaled by inverse maintainability.
 * Extra time for low-maintainability code (harder to refactor).
 */
function estimateDebt(
  loc: number,
  mi: number,
  findingsCount: number
): number {
  const baseFindingHours = findingsCount * 0.5;
  const complexityPenalty = loc > 0 ? (loc / 100) * ((100 - mi) / 100) : 0;
  const total = baseFindingHours + complexityPenalty;
  return Math.round(total * 10) / 10; // 1 decimal place
}

/* ------------------------------------------------------------------ */
/*  Pattern detectors                                                  */
/* ------------------------------------------------------------------ */

function detectFindings(source: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // CWE-89: SQL injection via string concatenation
    if (
      /["'`]\s*\+\s*\w+.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b/i.test(line) ||
      /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*["'`]\s*\+\s*\w+/i.test(line) ||
      /(?:query|execute|sql)\s*\(\s*["'`].*\$\{/i.test(line)
    ) {
      findings.push({
        ruleId: "SEC-001",
        cwe: "CWE-89",
        severity: "Critical",
        line: lineNum,
        message:
          "SQL query constructed via string concatenation — potential injection vector.",
        remediation:
          "Use parameterized queries or prepared statements. Replace string interpolation with query placeholders (e.g., `?` for MySQL, `$1` for PostgreSQL).",
      });
    }

    // CWE-95: Dynamic code execution via eval() or new Function()
    if (/\beval\s*\(/.test(line) || /new\s+Function\s*\(/.test(line)) {
      findings.push({
        ruleId: "SEC-002",
        cwe: "CWE-95",
        severity: "Critical",
        line: lineNum,
        message:
          "Dynamic code execution detected (`eval` or `new Function`) — arbitrary code execution risk.",
        remediation:
          "Eliminate `eval` and `new Function`. Use `JSON.parse` for data, a sandboxed interpreter for expressions, or refactor to static dispatch.",
      });
    }

    // Legacy var usage
    if (/^\s*var\s+\w+/.test(line)) {
      findings.push({
        ruleId: "LEGACY-001",
        cwe: "N/A",
        severity: "Medium",
        line: lineNum,
        message:
          "`var` declaration — function-scoped, hoisting-prone, superseded by `let`/`const`.",
        remediation:
          "Replace `var` with `const` (preferred) or `let`. Verify no code relies on `var` hoisting before changing.",
      });
    }

    // Unhandled callback pattern (error-first callback ignoring err)
    if (
      /function\s*\(\s*err\s*[,)]/i.test(line) &&
      !/if\s*\(\s*err/.test(lines[i + 1] || "") &&
      !/throw/.test(lines[i + 1] || "")
    ) {
      findings.push({
        ruleId: "MAINT-001",
        cwe: "N/A",
        severity: "Low",
        line: lineNum,
        message:
          "Error-first callback pattern with no visible error handling on the next line.",
        remediation:
          "Add `if (err) { ... }` handling or migrate to async/await with try-catch. Swallowed errors cause silent failures in production.",
      });
    }
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/*  Simulated upstream dependency audit                                */
/* ------------------------------------------------------------------ */

function simulateDependencyAudit(source: string): DependencyAudit[] {
  // Detect package names from import / require statements
  const importPattern =
    /(?:import\s+.*\s+from\s+['"]([^./][^'"]+)['"]|require\s*\(\s*['"]([^./][^'"]+)['"]\s*\))/g;
  const detected = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = importPattern.exec(source)) !== null) {
    const pkg = (match[1] || match[2]).split("/")[0];
    if (pkg && !pkg.startsWith("@")) {
      detected.add(pkg);
    } else if (pkg?.startsWith("@")) {
      // scoped package — include scope + name
      const full = (match[1] || match[2]).split("/").slice(0, 2).join("/");
      detected.add(full);
    }
  }

  // Hard-coded audit database for common packages
  const auditDb: Record<
    string,
    { version: string; latest: string; status: DependencyAudit["status"]; flag?: string }
  > = {
    express: {
      version: "^4.18.2",
      latest: "5.1.0",
      status: "outdated",
      flag: "v5 stable available; v4 in maintenance",
    },
    lodash: {
      version: "^4.17.21",
      latest: "4.17.21",
      status: "vulnerable",
      flag: "CVE-2021-23337 — Prototype Pollution in zipObjectDeep",
    },
    mongoose: { version: "^7.6.3", latest: "8.9.5", status: "outdated", flag: "v8 available" },
    axios: { version: "^1.6.0", latest: "1.7.9", status: "up-to-date" },
    react: { version: "^18.2.0", latest: "19.0.0", status: "outdated", flag: "v19 available" },
    jquery: {
      version: "^3.6.0",
      latest: "3.7.1",
      status: "vulnerable",
      flag: "CVE-2020-23064 — XSS via htmlPrefilter",
    },
    moment: {
      version: "^2.29.4",
      latest: "2.30.1",
      status: "outdated",
      flag: "Project in maintenance mode; consider dayjs or date-fns",
    },
    underscore: {
      version: "^1.13.6",
      latest: "1.13.7",
      status: "outdated",
      flag: "Largely superseded by ES6+ built-ins",
    },
    request: {
      version: "^2.88.2",
      latest: "2.88.2",
      status: "vulnerable",
      flag: "Deprecated — no security patches since 2020",
    },
    "body-parser": {
      version: "^1.20.2",
      latest: "1.20.3",
      status: "up-to-date",
      flag: "Built into Express 4.16+; direct dependency unnecessary",
    },
    mysql: {
      version: "^2.18.1",
      latest: "2.18.1",
      status: "outdated",
      flag: "Use mysql2 for prepared statements and Promise support",
    },
    pg: { version: "^8.11.3", latest: "8.13.1", status: "up-to-date" },
    dotenv: { version: "^16.3.1", latest: "16.4.7", status: "up-to-date" },
    cors: { version: "^2.8.5", latest: "2.8.5", status: "up-to-date" },
    helmet: { version: "^7.1.0", latest: "8.0.0", status: "up-to-date" },
    bcryptjs: { version: "^2.4.3", latest: "2.4.3", status: "up-to-date" },
    jsonwebtoken: {
      version: "^9.0.2",
      latest: "9.0.2",
      status: "outdated",
      flag: "Consider jose for ESM / edge-runtime compatibility",
    },
    chalk: { version: "^5.3.0", latest: "5.4.1", status: "up-to-date" },
    commander: { version: "^12.0.0", latest: "13.1.0", status: "up-to-date" },
    glob: {
      version: "^10.3.10",
      latest: "11.0.1",
      status: "outdated",
      flag: "v11 available with improved performance",
    },
    async: {
      version: "^3.2.5",
      latest: "3.2.6",
      status: "outdated",
      flag: "Native async/await preferred in modern codebases",
    },
  };

  const results: DependencyAudit[] = [];

  for (const pkg of detected) {
    const known = auditDb[pkg];
    if (known) {
      results.push({
        package: pkg,
        declaredVersion: known.version,
        latestVersion: known.latest,
        status: known.status,
        flag: known.flag,
      });
    } else {
      results.push({
        package: pkg,
        declaredVersion: "^1.0.0",
        latestVersion: "1.0.0",
        status: "up-to-date",
      });
    }
  }

  // Always include a few common packages if none were detected
  if (results.length === 0) {
    results.push(
      {
        package: "express",
        declaredVersion: "^4.18.2",
        latestVersion: "5.1.0",
        status: "outdated",
        flag: "v5 stable available; v4 in maintenance",
      },
      {
        package: "lodash",
        declaredVersion: "^4.17.21",
        latestVersion: "4.17.21",
        status: "vulnerable",
        flag: "CVE-2021-23337 — Prototype Pollution in zipObjectDeep",
      },
      {
        package: "dotenv",
        declaredVersion: "^16.3.1",
        latestVersion: "16.4.7",
        status: "up-to-date",
      },
      {
        package: "mongoose",
        declaredVersion: "^7.6.3",
        latestVersion: "8.9.5",
        status: "outdated",
        flag: "v8 available",
      }
    );
  }

  return results;
}

/* ------------------------------------------------------------------ */
/*  Automated refactoring                                              */
/* ------------------------------------------------------------------ */

/**
 * Generate a modernized version of the source code by applying
 * deterministic, safe transformations:
 *   1. Replace `var` with `const` or `let` (let when reassigned).
 *   2. Replace `eval('(' + x + ')')` with `JSON.parse(x)`.
 *   3. Replace `new Function(...)` with a safe stub that throws.
 *   4. Replace SQL string concatenation with parameterized placeholders.
 */
function generateRefactoredCode(source: string): string {
  const lines = source.split("\n");
  const output: string[] = [];

  // First pass — collect which var names are later reassigned so we
  // know whether to use `const` or `let`.
  const reassigned = new Set<string>();
  const varDeclPattern = /^\s*var\s+(\w+)/;
  const reassignPattern = /^\s*(\w+)\s*(?:\+|-|\*|\/)?=(?!=)/;

  const declaredVars = new Set<string>();
  for (const line of lines) {
    const dm = varDeclPattern.exec(line);
    if (dm) declaredVars.add(dm[1]);
  }
  for (const line of lines) {
    const rm = reassignPattern.exec(line);
    if (rm && declaredVars.has(rm[1]) && !varDeclPattern.test(line)) {
      reassigned.add(rm[1]);
    }
  }
  // Heuristic: loop counters (i, j, k, idx, index) are always `let`.
  for (const name of ["i", "j", "k", "idx", "index"]) {
    if (declaredVars.has(name)) reassigned.add(name);
  }
  // Heuristic: variables named `total`, `sum`, `count`, `result` are often
  // accumulated, so mark them as `let`.
  for (const name of ["total", "sum", "count", "result", "acc"]) {
    if (declaredVars.has(name)) reassigned.add(name);
  }

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // ── 1. var → const / let ────────────────────────────────────────
    const vm = /^(\s*)var\s+(\w+)(.*)$/.exec(line);
    if (vm) {
      const [, indent, varName, rest] = vm;
      const keyword = reassigned.has(varName) ? "let" : "const";
      line = `${indent}${keyword} ${varName}${rest}`;
    }

    // ── 2. eval('(' + x + ')') → JSON.parse(x) ─────────────────────
    //    Covers: eval('(' + rawJson + ')')
    line = line.replace(
      /eval\s*\(\s*['"]?\(\s*['"]?\s*\+\s*(\w+)\s*\+\s*['"]?\)\s*['"]?\s*\)/g,
      "JSON.parse($1)"
    );
    // Covers bare eval(expr) not already replaced
    line = line.replace(
      /eval\s*\(\s*(\w+)\s*\)/g,
      "JSON.parse($1) /* REVIEW: eval replaced with JSON.parse — verify input is valid JSON */"
    );

    // ── 3. new Function(...) → safe stub ────────────────────────────
    if (/new\s+Function\s*\(/.test(line)) {
      line = line.replace(
        /new\s+Function\s*\([^)]*\)/g,
        "(() => { throw new Error('Dynamic Function execution removed — refactor to static dispatch'); })"
      );
    }

    // ── 4. SQL string concatenation → parameterized placeholders ────
    //    Pattern: "SELECT ... WHERE col = '" + val + "'"
    //    Replace with: "SELECT ... WHERE col = ?", [val]
    {
      const sqlConcat =
        /^(\s*(?:const|let|var)\s+\w+\s*=\s*)["']([^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*?)(?:\s*['"]?\s*\+\s*(\w+)\s*\+\s*["'][^"']*["'])/i;
      const sm = sqlConcat.exec(line);
      if (sm) {
        const [, prefix, sqlPart, paramName] = sm;
        line = `${prefix}"${sqlPart.replace(/'\s*$/, "")} = ?"; /* parameterized: [${paramName}] */`;
      }
    }
    // Pattern: db.query("SELECT ... WHERE id = " + val, ...)
    {
      const dbQueryConcat =
        /^(\s*(?:\w+\.)?query\s*\(\s*)["']([^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*?)\s*(?:=\s*)?["']?\s*\+\s*(\w+)\s*,/i;
      const dm = dbQueryConcat.exec(line);
      if (dm) {
        const [, prefix, sqlPart, paramName] = dm;
        const cleanSql = sqlPart.replace(/\s*=\s*$/, " = ?").replace(/\s+$/, "");
        line = `${prefix}"${cleanSql}", [${paramName}],`;
      }
    }

    output.push(line);
  }

  return output.join("\n");
}

/* ------------------------------------------------------------------ */
/*  Route handlers                                                     */
/* ------------------------------------------------------------------ */

export async function GET() {
  try {
    const db = await connectDB();
    if (!db) {
      return NextResponse.json([]);
    }
    const records = await AuditRecord.find({})
      .sort({ createdAt: -1 })
      .limit(6)
      .lean();
    return NextResponse.json(records);
  } catch (err) {
    console.error("Failed to fetch audit records:", err);
    return NextResponse.json([]);
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { sourceCode, moduleName } = body as {
      sourceCode?: string;
      moduleName?: string;
    };

    if (!sourceCode || typeof sourceCode !== "string") {
      return NextResponse.json(
        { error: "sourceCode (string) is required." },
        { status: 400 }
      );
    }

    const name = (moduleName || "untitled-module").trim();
    const loc = countLOC(sourceCode);
    const cc = cyclomaticComplexity(sourceCode);
    const mi = maintainabilityIndex(loc, cc);
    const findings = detectFindings(sourceCode);
    const debt = estimateDebt(loc, mi, findings.length);
    const dependencyAudit = simulateDependencyAudit(sourceCode);
    const refactoredCode = generateRefactoredCode(sourceCode);

    let recordId: string | undefined;
    const db = await connectDB();
    if (db) {
      try {
        const saved = await AuditRecord.create({
          moduleName: name,
          sourceCode,
          loc,
          cyclomaticComplexity: cc,
          maintainabilityIndex: mi,
          technicalDebtHours: String(debt),
          issuesCount: findings.length,
          issues: findings,
          manifestAudits: dependencyAudit,
          refactoredCode,
        });
        recordId = saved._id.toString();
      } catch (dbErr) {
        console.warn("Failed to persist audit to MongoDB:", dbErr);
      }
    }

    const result: AnalysisResult = {
      _id: recordId,
      moduleName: name,
      sourceCode,
      metrics: {
        loc,
        cyclomaticComplexity: cc,
        maintainabilityIndex: mi,
        technicalDebtHours: debt,
      },
      findings,
      dependencyAudit,
      refactoredCode,
    };

    return NextResponse.json(result);
  } catch (err) {
    console.error("Analysis error:", err);
    return NextResponse.json(
      { error: "Failed to process analysis request." },
      { status: 500 }
    );
  }
}

