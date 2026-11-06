# Upkeep // DevSecOps Static Analysis & Codebase Telemetry

Upkeep is a static code analysis, vulnerability detection, and automated refactoring platform built with Next.js App Router, TypeScript, Tailwind CSS, and MongoDB Atlas.

---

## Key Features

1. **AST Static Code Analysis:** Deterministically inspects JavaScript/Node.js code syntax trees instead of relying on basic regex.
2. **Vulnerability Detection (CWE Compliance):**
   - `SEC-001 (CWE-89)`: Flags dynamic SQL string concatenation susceptible to SQL injection.
   - `SEC-002 (CWE-95)`: Detects dangerous execution flows (`eval()`, dynamic code evaluation).
   - `LEGACY-001`: Flags hoisting-prone, function-scoped `var` statements.
3. **Deterministic Engineering Metrics:**
   - **Maintainability Index (MI):** Computed logarithmic score based on volume and complexity.
   - **McCabe Cyclomatic Complexity:** Identifies independent branch paths.
   - **Technical Debt Estimation:** Quantifies hours needed for remediation.
4. **Automated Safe Remediation:** Synthesizes unified ES6 diff patches to remediate legacy code.
5. **MongoDB Atlas Persistence:** Stores every scan run into a live MongoDB Atlas cluster for historical telemetry review.
6. **SARIF v2.1.0 Export:** Generates industry-standard OASIS SARIF files compatible with GitHub CodeQL and CI/CD security workflows.

---

## Tech Stack

- **Framework:** Next.js (App Router, React, TypeScript)
- **Styling:** Tailwind CSS (Enterprise Slate/Zinc Palette)
- **Database:** MongoDB Atlas (M0 Cluster via Mongoose ODM)
- **Standards:** OASIS SARIF v2.1.0

---

## Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/upkeep.git
cd upkeep