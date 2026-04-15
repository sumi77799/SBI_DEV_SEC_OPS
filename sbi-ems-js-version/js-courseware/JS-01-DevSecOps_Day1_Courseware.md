# DevSecOps — Intermediate | Participant Courseware
## DAY 1
**Secure Coding · SAST · DAST · Secrets Management · CI/CD Integration**

*Project: SBI Employee Management System (EMS) — Node.js / Express.js*
*State Bank of India — Technology Training Programme*

---

## Day 1 Schedule

| Time | Session | Topics |
|---|---|---|
| 10:30 – 11:30 | **Secure Coding Practices** | OWASP Top 10, injection, broken auth, code-level controls on EMS |
| 11:30 – 12:15 | **SAST Concepts + Tools** | Static analysis, SonarQube, taint analysis, EMS scan walkthrough |
| 12:15 – 12:30 | Break | — |
| 12:30 – 1:30 | **Lab 1: SAST Scan + Fix** | Hands-on SonarQube scan of EMS, triage, remediation |
| 1:30 – 2:15 | **DAST Concepts + Tools** | Dynamic testing, OWASP ZAP, scanning running apps |
| 2:15 – 3:00 | Lunch | — |
| 3:00 – 4:00 | **Lab 2: DAST Scan** | ZAP active scan of EMS, vulnerability analysis |
| 4:00 – 4:45 | **Secrets Management** | HashiCorp Vault, git-secrets, best practices |
| 4:45 – 5:15 | **CI/CD Integration** | Pipeline gates, SAST+DAST in GitHub Actions |
| 5:15 – 5:30 | Lab + Q&A | Wrap-up, open questions |

---

# Module 1: Secure Coding Practices
`10:30 – 11:30` · OWASP Top 10 · Input Validation · Authentication · Error Handling

Secure coding is the practice of writing software that is resilient to attack from the moment it is written — not as an afterthought. For a banking application like EMS, a single exploitable flaw in a REST endpoint can expose salary data, enable unauthorized access to employee records, or allow an attacker to pivot deeper into the bank's network. This module covers the most common vulnerability classes and how to eliminate them at the code level.

## 1.1 Why Secure Coding Matters in Banking

Banks are among the most targeted organisations in the world. RBI's IT Framework for Banks (2011, updated 2023) and CERT-In directives mandate that development teams follow secure coding standards. The cost of a post-deployment fix is 6–100x higher than catching the same issue at code review. The EMS application — though built as a training vehicle — uses the same patterns, frameworks, and data types (PII: salary, email, phone) found in real banking systems, making it an ideal sandbox to learn these concepts without real risk.

## 1.2 The OWASP Top 10 — Banking Context

The Open Web Application Security Project (OWASP) publishes a Top 10 list of the most critical web application security risks. Every item on this list has caused real incidents at financial institutions. We cover each one with an EMS-specific example.

---

### A01:2021 — Broken Access Control

Broken Access Control is the #1 risk. It occurs when the application does not properly enforce what authenticated users are allowed to do. In banking, this means one user can read or modify another user's data.

**EMS Example** — The salary field is PII. Only the employee themselves and HR Admins should see it. A broken access control vulnerability would allow any authenticated user to call:

```
GET /api/v1/employees/42  →  returns { salary: 125000 } to ANY authenticated user
```

The fix is Role-Based Access Control (RBAC) enforced via a dedicated `authorize` middleware:

```javascript
// middleware/authorize.js — reusable RBAC middleware
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'Unauthenticated' });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
};

// routes/employeeRoutes.js — VULNERABLE (no access control)
router.get('/:id', employeeController.getById);

// routes/employeeRoutes.js — SECURE (RBAC + salary masking)
router.get('/:id', authenticate, employeeController.getById);

// controllers/employeeController.js — mask salary for non-admin callers
exports.getById = async (req, res) => {
  const employee = await employeeService.findById(req.params.id);
  const isAdminOrSelf =
    req.user.role === 'ADMIN' || req.user.id === employee.id;

  const result = isAdminOrSelf
    ? employee.toJSON()
    : { ...employee.toJSON(), salary: undefined }; // mask PII

  res.json(result);
};
```

> **Key Principle:** Always enforce authorization at the SERVICE layer, not just at the API gateway or route level. Defence in depth means every layer checks permissions independently.

---

### A02:2021 — Cryptographic Failures

Cryptographic failures (formerly 'Sensitive Data Exposure') occur when sensitive data is transmitted or stored without adequate encryption. In EMS, the salary, email, and phone fields are PII and must never appear in plain text in logs, error messages, or unencrypted storage.

- Always use HTTPS (TLS 1.2+). Use a reverse proxy (Nginx/Caddy) or set `NODE_ENV=production` with an HTTPS server.
- Never log sensitive fields. Strip PII before passing objects to the logger.
- Store passwords using `bcrypt` — never MD5, SHA-1, or plain text.
- Database columns holding PII should use column-level encryption where the database supports it (MySQL Enterprise Encryption).

```javascript
// Correct password hashing with bcrypt
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// On registration
const hashedPassword = await bcrypt.hash(plainPassword, SALT_ROUNDS);

// On login
const isValid = await bcrypt.compare(plainPassword, storedHash);

// Masking in logs — never log the raw employee object
const safeLog = (employee) => ({
  id: employee.id,
  email: '[REDACTED]',
  salary: '[REDACTED]',
});
logger.info('Employee accessed', safeLog(employee));
```

---

### A03:2021 — Injection

Injection attacks — SQL injection, NoSQL injection, command injection — occur when untrusted data is sent to an interpreter as part of a command or query. SQL injection remains devastatingly common in banking applications and can expose entire databases or allow data manipulation.

EMS uses Sequelize ORM, which uses parameterized queries by default. However, raw queries or string interpolation in queries can introduce injection:

```javascript
const { Op } = require('sequelize');

// VULNERABLE — raw SQL with string interpolation
const employees = await sequelize.query(
  `SELECT * FROM Employees WHERE departmentName = '${deptName}'`
);

// SAFE — Sequelize parameterized query (uses ? placeholders internally)
const employees = await sequelize.query(
  'SELECT * FROM Employees WHERE departmentName = ?',
  { replacements: [deptName], type: QueryTypes.SELECT }
);

// SAFEST — Sequelize model method (no SQL string at all)
const employees = await Employee.findAll({
  include: [{ model: Department, where: { name: deptName } }]
});
```

> **Banking-Specific Risk:** SQL injection on an employee search endpoint could allow an attacker to extract ALL employee salary records with a single crafted query: `?dept=' OR '1'='1`. In a real bank system, this could mean mass PII exposure triggering RBI data breach notification requirements.

---

### A04:2021 — Insecure Design

Insecure design means architectural or design-level flaws that cannot be fixed by implementation alone. In EMS, the business rule "a project cannot move directly from PLANNED to COMPLETED" is a design control — if it is not enforced at the service layer, no amount of route-level validation will prevent it.

```javascript
// services/projectService.js — enforce project lifecycle state machine
const VALID_TRANSITIONS = {
  PLANNED:   ['ACTIVE', 'CANCELLED'],
  ACTIVE:    ['ON_HOLD', 'COMPLETED', 'CANCELLED'],
  ON_HOLD:   ['ACTIVE', 'CANCELLED'],
  COMPLETED: [],
  CANCELLED: [],
};

exports.updateStatus = async (id, newStatus) => {
  const project = await Project.findByPk(id);
  const allowed = VALID_TRANSITIONS[project.status] || [];

  if (!allowed.includes(newStatus)) {
    const err = new Error(
      `Invalid transition: ${project.status} → ${newStatus}`
    );
    err.statusCode = 422;
    throw err;
  }
  project.status = newStatus;
  return project.save();
};
```

---

### A05:2021 — Security Misconfiguration

Security misconfiguration is extremely common in Express.js applications — particularly around HTTP headers, CORS, and accidentally exposed debug information.

- Express exposes the `X-Powered-By: Express` header by default — remove it to reduce fingerprinting.
- CORS must be explicitly configured — do not use `cors()` with no options in banking apps.
- Error messages must not leak stack traces or internal paths to the caller.
- Use the `helmet` package to set secure HTTP headers automatically.

```javascript
// app.js — EMS secure Express configuration
const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const app     = express();

// Remove fingerprinting header
app.disable('x-powered-by');

// Set secure HTTP headers (CSP, HSTS, X-Content-Type-Options, etc.)
app.use(helmet());

// Explicit CORS — only allow the internal SBI portal origin
app.use(cors({
  origin: 'https://ems.sbi.internal',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}));

// Never expose stack traces in production
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(err.statusCode || 500).json({ message: 'Internal server error' });
  } else {
    res.status(err.statusCode || 500).json({ message: err.message, stack: err.stack });
  }
});
```

---

### A06:2021 — Vulnerable and Outdated Components

Using npm packages with known CVEs is a common attack vector. The Node.js ecosystem has had critical vulnerabilities (prototype pollution in `lodash`, RCE in `vm2`, path traversal in `express-fileupload`). Banking teams must maintain a Software Bill of Materials (SBOM) and monitor for CVEs.

- Use `npm audit` to scan dependencies for known vulnerabilities.
- Regularly run `npm outdated` and pin versions in `package.json`.
- Subscribe to GitHub Security Advisories for your key dependencies.

```bash
# Scan EMS npm dependencies for known CVEs
npm audit

# Auto-fix non-breaking vulnerabilities
npm audit fix

# Full dependency CVE scan with OWASP Dependency-Check
dependency-check.sh --project EMS --scan . --format HTML
```

---

### A07:2021 — Identification and Authentication Failures

EMS uses JWT (JSON Web Token) for stateless authentication via the `jsonwebtoken` npm package. Improper JWT implementation is a critical vulnerability class — attackers can forge tokens, bypass expiry, or exploit weak signing secrets.

```javascript
const jwt = require('jsonwebtoken');

// MISTAKE 1 — weak signing secret hardcoded in source
const SECRET = 'secret123'; // NEVER DO THIS

// CORRECT — read from environment variable
const SECRET = process.env.JWT_SECRET;

// MISTAKE 2 — no expiry on token
const token = jwt.sign({ id: user.id }, SECRET);

// CORRECT — short-lived tokens (15 min for banking)
const token = jwt.sign(
  { id: user.id, role: user.role },
  SECRET,
  { expiresIn: '15m', algorithm: 'HS256' }
);

// middleware/authenticate.js — verify token on every protected route
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ message: 'Missing token' });

  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};
```

---

### A08:2021 — Software and Data Integrity Failures

This covers CI/CD pipeline poisoning and insecure deserialization. In a DevSecOps context, it means your build pipeline itself must be secured — a compromised pipeline can inject malicious code into deployable artifacts.

- Never use `*` versions in `package.json` for production dependencies — pin to exact versions.
- Use `package-lock.json` and commit it; verify `npm ci` (not `npm install`) in CI for reproducible builds.
- Restrict write access to pipeline configuration files.

---

### A09:2021 — Security Logging and Monitoring Failures

Banks are required by RBI to maintain audit logs for access to sensitive data. EMS uses the `winston` logger and should be wired to a SIEM. At minimum, log all authentication events, all access to salary data, and all failed authorization attempts.

```javascript
// middleware/auditLogger.js — log every salary access
const winston = require('winston');
const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'audit.log' })],
});

// Express middleware — wrap the getEmployee controller
const auditSalaryAccess = (req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    if (body?.salary !== undefined) {
      auditLogger.info({
        event:      'SALARY_ACCESS',
        user:       req.user?.email,
        employeeId: req.params.id,
        timestamp:  new Date().toISOString(),
        ip:         req.ip,
      });
    }
    return originalJson(body);
  };
  next();
};

// Apply to the employee GET route
router.get('/:id', authenticate, auditSalaryAccess, employeeController.getById);
```

---

### A10:2021 — Server-Side Request Forgery (SSRF)

SSRF allows an attacker to make the server issue HTTP requests to internal resources — useful for probing internal bank infrastructure, accessing cloud metadata endpoints (AWS/GCP IMDS), or bypassing firewall rules.

- Validate and whitelist any URL parameter your application fetches.
- Never allow user-controlled input to directly form an outbound request URL.
- In banking cloud deployments, the AWS instance metadata endpoint (`169.254.169.254`) is a primary SSRF target.

---

## 1.3 Input Validation — The First Line of Defence

EMS uses `express-validator` for input validation. Every field that accepts user input must be validated for type, length, format, and business rules before it reaches the service layer.

```javascript
// validators/employeeValidator.js — comprehensive validation rules
const { body, validationResult } = require('express-validator');

exports.createEmployeeRules = [
  body('firstName')
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be 2–50 characters')
    .matches(/^[a-zA-Z\s-]+$/).withMessage('First name must contain only letters, spaces, or hyphens'),

  body('email')
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email address')
    .normalizeEmail(),

  body('salary')
    .notEmpty().withMessage('Salary is required')
    .isFloat({ min: 0.01, max: 9999999.99 }).withMessage('Salary must be a positive value'),

  body('hireDate')
    .notEmpty().withMessage('Hire date is required')
    .isDate().withMessage('Must be a valid date')
    .custom((val) => {
      if (new Date(val) > new Date()) throw new Error('Hire date cannot be in the future');
      return true;
    }),
];

// middleware/validate.js — reusable validation error handler
exports.validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array() });
  }
  next();
};

// routes/employeeRoutes.js — wire up validation
const { createEmployeeRules } = require('../validators/employeeValidator');
const { validate } = require('../middleware/validate');

router.post('/',
  authenticate,
  authorize('ADMIN'),
  createEmployeeRules,
  validate,
  employeeController.create
);
```

## 1.4 Secure Error Handling

Error messages are intelligence for attackers. A stack trace revealing file paths, database types, or internal module names gives an attacker a significant advantage. EMS must use a global error handler middleware that returns safe, generic messages to the client while logging full detail internally.

```javascript
// middleware/errorHandler.js — EMS global error handler
const { v4: uuidv4 } = require('uuid');
const logger = require('../config/logger');

const errorHandler = (err, req, res, next) => {
  const correlationId = uuidv4();

  // Always log the full detail internally
  logger.error({
    correlationId,
    method:  req.method,
    url:     req.originalUrl,
    message: err.message,
    stack:   err.stack,
  });

  // Validation errors — safe to return field-level detail
  if (err.name === 'ValidationError' || err.statusCode === 400) {
    return res.status(400).json({
      message: 'Validation failed',
      errors:  err.errors || err.message,
    });
  }

  // All other errors — NEVER expose internals to the client
  res.status(err.statusCode || 500).json({
    message:       'An internal error occurred.',
    correlationId, // reference ID for support — matches internal log entry
  });
};

module.exports = errorHandler;

// app.js — register as the last middleware
app.use(errorHandler);
```

> **RBI Compliance Note:** RBI's IT Framework Section 3.2 requires that error messages do not disclose system internals. The pattern above (log detail internally + return correlation ID externally) satisfies this requirement and enables incident tracing without exposing sensitive data.

---

# Module 2: Static Application Security Testing (SAST)
`11:30 – 12:15` · SonarQube · Semgrep · Taint Analysis · CI Integration

Static Application Security Testing analyses source code for security vulnerabilities **without executing the application**. It is the shift-left cornerstone of DevSecOps — finding defects early in the pipeline when they are cheapest to fix.

## 2.1 How SAST Works

SAST tools build an Abstract Syntax Tree (AST) or Control Flow Graph (CFG) from your source code and then apply these analysis techniques:

| Technique | What it detects |
|---|---|
| Pattern matching | Simple anti-patterns: deprecated APIs, hardcoded strings, obvious injection patterns |
| Taint analysis | Tracks user-controlled data ('tainted' sources) through the codebase to sensitive operations ('sinks'). Finds injection, XSS, SSRF. |
| Data flow analysis | Detects null/undefined dereferences, resource leaks, use-after-free patterns |
| Control flow analysis | Detects unreachable code, infinite loops, improper error propagation |

## 2.2 SAST in the DevSecOps Pipeline

SAST fits at two points: in the developer's IDE (real-time feedback via SonarLint) and in the CI pipeline (gate on pull request or commit to main).

```
Developer writes code
    │
    ▼
SonarLint (VS Code extension) ──► highlights issues in real-time
    │
    ▼
git push / pull request
    │
    ▼
CI Pipeline: npx sonar-scanner ──► SonarQube server analysis
    │                               reports to PR / breaks build
    ▼
Quality Gate PASS / FAIL
```

## 2.3 SonarQube — Key Concepts

- **Rules:** Individual checks. SonarQube ships 400+ JavaScript rules; security-relevant ones are tagged `owasp-top10`.
- **Issues:** A violation of a rule. Classified as Bug, Vulnerability, Security Hotspot, or Code Smell.
- **Quality Gate:** A configurable pass/fail condition (e.g. 'no new Critical vulnerabilities').
- **Security Hotspot:** Code that may or may not be a vulnerability — requires human review.

| Severity | Meaning | Example in EMS |
|---|---|---|
| Blocker | Must fix before deploy | Raw SQL string concatenation (injection risk) |
| Critical | Fix in current sprint | Hardcoded JWT secret in source |
| Major | Fix before next release | Missing input validation on a route handler |
| Minor | Fix opportunistically | `console.log` left in production code |
| Info | Informational only | Missing JSDoc on exported function |

## 2.4 Configuring SonarQube for EMS

```properties
# sonar-project.properties — in the project root (already present)
sonar.host.url=http://SONAR_SERVER_IP:9000
sonar.projectKey=sbi-ems
sonar.projectName=SBI Employee Management System
sonar.sources=src
sonar.exclusions=**/node_modules/**,**/test/**,**/coverage/**
sonar.javascript.lcov.reportPaths=coverage/lcov.info
```

```bash
# Run analysis (sonar-scanner installed globally on your VM)
npm test -- --coverage   # generate coverage report first
npx sonar-scanner -Dsonar.token=YOUR_TOKEN
```

## 2.5 Reading a SonarQube Report

After the scan completes, open the SonarQube dashboard. For each issue you will see:

- **Rule ID and description** — explains exactly what was found and why it matters.
- **File + line number** — click to open the code in the browser with the problematic line highlighted.
- **Effort** — estimated remediation time.
- **Data flow** — for taint analysis findings, SonarQube shows the complete path from source (user input) to sink (unsafe operation). This is the most valuable feature for understanding injection vulnerabilities.

> **Lab Preview:** In Lab 1 (12:30 – 1:30), you will run a real SonarQube scan on EMS and triage the findings. You will fix at least two Critical issues — a hardcoded credential and a missing authorization check — and re-run the scan to confirm the Quality Gate passes.

## 2.6 Semgrep — Lightweight Rule-Based Scanning

Semgrep is a fast, open-source SAST tool that runs rules expressed as code patterns. Unlike SonarQube (which requires a server), Semgrep runs entirely from the command line and is ideal for pre-commit hooks and CI pipelines.

```bash
# Scan EMS with OWASP Top 10 rules
semgrep --config=p/owasp-top-ten ./src

# Scan for JavaScript/Node.js-specific security issues
semgrep --config=p/javascript ./src

# Scan for Express.js security patterns
semgrep --config=p/nodejs ./src
```

```yaml
# Custom rule — detect hardcoded secrets in EMS
# rules/no-hardcoded-secrets.yaml
rules:
  - id: no-hardcoded-jwt-secret
    pattern: |
      const $SECRET = "..."
    message: Hardcoded secret detected — use process.env or Vault
    severity: ERROR
    languages: [javascript]
```

---

# Lab 1: SAST Scan + Fix
`12:30 – 1:30` · Hands-on SonarQube scan of EMS · Triage findings · Remediate two Critical issues

> **Lab Objective:** Run a SonarQube scan on the EMS project, understand the findings, fix two Critical security issues (hardcoded secret + missing authorization), re-scan, and verify the Quality Gate passes.

## Step 1 — Open the Project

1. Open VS Code.
2. **File > Open Folder** > select the `ems/` folder on your Desktop.
3. Open a Terminal inside VS Code (`Ctrl + `` `).

## Step 2 — Install Dependencies and Run Tests

```bash
npm install
npm test -- --coverage
```

Wait for tests to complete and the `coverage/` directory to be created. The coverage report is required by SonarQube.

## Step 3 — Run the SonarQube Scan

Your trainer will provide `SONAR_IP` and `TOKEN`:

```bash
npx sonar-scanner \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

At the end, the console prints a URL: `ANALYSIS SUCCESSFUL, you can find the results at: http://SONAR_IP:9000/dashboard?id=sbi-ems`

## Step 4 — Explore the Dashboard

1. Open the URL in Chrome.
2. Note the Quality Gate status (likely **FAILED** on first scan).
3. Click on **Vulnerabilities** in the left panel.
4. Click on the first Critical issue — read the rule description, the affected file, and the data flow diagram.
5. Answer: what is the user-controlled source, and what is the unsafe sink?

## Step 5 — Fix Issue 1: Hardcoded JWT Secret

Find the following code in `src/middleware/authenticate.js` or `src/config/jwt.js`:

```javascript
// BEFORE — hardcoded secret
const JWT_SECRET = 'SBIBankingSecretKey2024';
const JWT_EXPIRY  = '24h';
```

Replace with:

```javascript
// AFTER — read from environment variable
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY  = process.env.JWT_EXPIRY || '15m';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is not set');
}
```

Ensure `.env` (gitignored) contains:

```
JWT_SECRET=<generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))">
JWT_EXPIRY=15m
```

## Step 6 — Fix Issue 2: Missing Authorization on Salary Endpoint

Find the employee GET route in `src/routes/employeeRoutes.js`:

```javascript
// BEFORE — no access control
router.get('/:id', employeeController.getById);

// AFTER — authenticate + mask salary for non-admin callers
router.get('/:id', authenticate, employeeController.getById);
```

Update `src/controllers/employeeController.js`:

```javascript
exports.getById = async (req, res, next) => {
  try {
    const employee = await employeeService.findById(req.params.id);
    const isAdminOrSelf =
      req.user.role === 'ADMIN' || req.user.id === employee.id;
    const result = isAdminOrSelf
      ? employee.toJSON()
      : { ...employee.toJSON(), salary: undefined };
    res.json(result);
  } catch (err) {
    next(err);
  }
};
```

## Step 7 — Re-run the Scan

```bash
npm test -- --coverage
npx sonar-scanner \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

Refresh the SonarQube dashboard. Confirm: the two Critical issues are resolved and the Quality Gate shows **PASSED**.

> **Discussion:** What other issues did you notice in the dashboard? Make a note of the top 3 findings you would fix next. We will revisit these during the Day 1 wrap-up.

---

# Module 3: Dynamic Application Security Testing (DAST)
`1:30 – 2:15` · OWASP ZAP · Active Scanning · API Fuzzing · Vulnerability Analysis

Where SAST analyses code without running it, DAST tests the **live, running application** from the outside — exactly as an attacker would. DAST sends malicious inputs (SQL injection strings, XSS payloads, authentication bypass attempts) to your application's HTTP endpoints and analyses the responses for vulnerabilities.

## 3.1 SAST vs DAST — Complementary, Not Competing

| SAST | DAST |
|---|---|
| Analyses source code | Analyses the running application via HTTP |
| No application needed to run | Application must be running |
| Finds issues early (pre-deployment) | Finds issues closer to production reality |
| Can miss runtime issues (config, deployment) | Catches runtime issues SAST cannot see |
| Higher false positive rate on complex flows | Lower false positives — confirms exploitability |
| Good for: injection, hardcoded secrets, access control logic | Good for: auth bypass, session issues, header misconfigs, SSRF |

> **DevSecOps Practice:** Run SAST on every commit. Run DAST on every deployment to the staging environment. Both are required — a vulnerability that SAST misses (e.g. a misconfigured CORS header set via an environment variable) will almost certainly be caught by DAST.

## 3.2 OWASP ZAP — Architecture and Modes

OWASP ZAP (Zed Attack Proxy) is the most widely used open-source DAST tool. It operates as an HTTP proxy that sits between your browser (or test scripts) and the target application.

- **Spider:** Crawls the application, discovers endpoints by following links and forms.
- **AJAX Spider:** Handles JavaScript-heavy SPAs by using a real browser engine.
- **Active Scan:** Sends attack payloads to each discovered parameter. This is the DAST scan proper.
- **Passive Scan:** Analyses traffic passing through the proxy without sending any additional requests. Safe to run against production.
- **Fuzzer:** Sends a wordlist of payloads to a specific parameter — useful for targeted injection testing.

## 3.3 Understanding ZAP Alerts

| Risk Level | CVSS Range | Examples |
|---|---|---|
| High | 7.0 – 10.0 | SQL injection, RCE, authentication bypass |
| Medium | 4.0 – 6.9 | Missing security headers, weak cipher suites |
| Low | 0.1 – 3.9 | Information disclosure, verbose error messages |
| Informational | N/A | Fingerprinting data (server version headers) |

## 3.4 Scanning EMS with ZAP

EMS exposes a REST API — we use the OpenAPI (Swagger) specification generated by `swagger-jsdoc` to import all endpoints into ZAP automatically.

```bash
# Step 1 — Start EMS
docker compose up -d

# Step 2 — Confirm OpenAPI spec is available
curl http://localhost:3000/api-docs.json | python -m json.tool | head -30

# Step 3 — Import into ZAP
# ZAP GUI: Import > Import an OpenAPI definition from a URL
# URL: http://localhost:3000/api-docs.json

# Step 4 — Configure JWT authentication
# Token obtained from: POST /api/v1/auth/login

# Step 5 — Active Scan
# Right-click the EMS context > Attack > Active Scan
```

## 3.5 Interpreting DAST Findings for EMS

| Finding | Affected EMS Endpoint | Remediation |
|---|---|---|
| Missing Content-Security-Policy header | All endpoints | Add via `helmet`: `app.use(helmet.contentSecurityPolicy(...))` |
| X-Content-Type-Options not set | All endpoints | `helmet` sets this by default — ensure `app.use(helmet())` is first |
| Verbose error messages in 500 responses | `/api/v1/employees` | Use `errorHandler` middleware (Module 1 — already fixed) |
| JWT token in URL parameter | `/api/v1/auth/**` | Always send JWT in `Authorization` header, never in URL |
| CORS: `Access-Control-Allow-Origin: *` | All endpoints | Restrict in `cors()` options: `origin: 'https://ems.sbi.internal'` |

## 3.6 Adding Security Headers to EMS

```javascript
// app.js — full helmet + CORS configuration
const helmet = require('helmet');
const cors   = require('cors');

// helmet sets: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and more
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));

// Strict CORS
app.use(cors({
  origin:         'https://ems.sbi.internal',
  methods:        ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}));
```

---

# Lab 2: DAST Scan + Vulnerability Analysis
`3:00 – 4:00` · OWASP ZAP active scan of running EMS · Analyse alerts · Add security headers

> **Lab Objective:** Start EMS, import its OpenAPI spec into ZAP, run an active scan, analyse the findings, and apply the CORS + security header fixes from Module 3.

## Step 1 — Start EMS

```bash
docker compose up -d
curl -s http://localhost:3000/health
```

## Step 2 — Open OWASP ZAP

1. Launch ZAP from your Desktop.
2. Select **"No, I do not want to persist this session"** for the lab.

## Step 3 — Import the OpenAPI Spec

1. In ZAP: **Import > Import an OpenAPI definition from a URL**.
2. Enter: `http://localhost:3000/api-docs.json`
3. Click Import. ZAP discovers all EMS endpoints automatically.

## Step 4 — Authenticate ZAP

```bash
# Get a JWT token
curl -s -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sbi.com","password":"Admin@123"}'
```

Copy the token and configure ZAP to inject the `Authorization: Bearer <token>` header on all requests.

## Step 5 — Run Active Scan

1. In the Sites panel: right-click `http://localhost:3000` > **Attack > Active Scan**.
2. The scan takes approximately 5–10 minutes.
3. Watch the **Alerts** tab populate with findings.

## Step 6 — Analyse Alerts

Sort by Risk (High > Medium > Low). For each High/Medium alert, record:

```
Alert Name:      ___________________________________
Risk Level:      High / Medium / Low
Affected URL:    ___________________________________
Description:     ___________________________________
Recommended fix: ___________________________________
```

## Step 7 — Apply Security Header Fix

Add the `helmet` and CORS configuration from Module 3 to `app.js`, then rebuild and re-scan:

```bash
docker compose down && docker compose up -d
# Re-run ZAP Active Scan — confirm header alerts disappear
```

> **Expected Result:** After adding the `helmet` headers, at least 2–3 Medium alerts should disappear.

---

# Module 4: Secrets Management
`4:00 – 4:45` · HashiCorp Vault · detect-secrets · Environment Variables · Best Practices

A **secret** is any sensitive configuration value that, if exposed, could lead to unauthorised access: database passwords, JWT signing keys, API keys, TLS private keys, and encryption keys.

## 4.1 The Secret Sprawl Problem

```javascript
// Pattern 1 — Hardcoded in source (appears in git history FOREVER)
const DB_PASSWORD = 'SBI_EMS_DB_2024!';

// Pattern 2 — In .env committed to git (equally dangerous)
// DB_PASSWORD=SBI_EMS_DB_2024!
```

```yaml
# Pattern 3 — In a Docker Compose file committed to git
environment:
  MYSQL_ROOT_PASSWORD: SBI_EMS_DB_2024!
```

> **Real Incident Pattern:** A bank developer accidentally committed an AWS access key to a public GitHub repository. Within 4 minutes, automated scanners had found it and used it to spin up crypto-mining instances. Incident response cost: $12,000 in cloud bills + regulatory notification. The key had been in the repository for 3 years before discovery.

## 4.2 Secret Detection — detect-secrets

```bash
# Scan the EMS repository for existing secrets
detect-secrets scan ./src > .secrets.baseline
detect-secrets audit .secrets.baseline

# Install as a pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
detect-secrets-hook --baseline .secrets.baseline
EOF
chmod +x .git/hooks/pre-commit

# Test: try to commit a file with a fake password
echo "DB_PASSWORD=SuperSecret123" > test.txt
git add test.txt && git commit -m "test"
# Expected: BLOCKED by pre-commit hook
```

## 4.3 Environment Variables with dotenv

```bash
# .env (in .gitignore — NEVER committed)
DB_HOST=localhost
DB_PORT=3306
DB_NAME=ems
DB_USER=ems_user
DB_PASSWORD=<secure-password>
JWT_SECRET=<256-bit-random-hex>
JWT_EXPIRY=15m
```

```javascript
// src/config/database.js — reference env vars, never hardcode
require('dotenv').config();

module.exports = {
  host:     process.env.DB_HOST     || 'localhost',
  port:     process.env.DB_PORT     || 3306,
  database: process.env.DB_NAME     || 'ems',
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // from environment, never hardcoded
  dialect:  'mysql',
};
```

```yaml
# docker-compose.yml — use .env file (gitignored)
services:
  ems:
    env_file: .env  # .env is in .gitignore — never committed
```

## 4.4 HashiCorp Vault — Enterprise Secrets Management

- **Dynamic secrets:** Vault generates short-lived, just-in-time database credentials. EMS's MySQL password rotates automatically — no static password to steal.
- **Audit log:** Every secret access is logged — who accessed what, when. Essential for RBI compliance.
- **Access policies:** Different applications get access only to the secrets they need (least privilege).
- **Secret leases:** Secrets expire automatically and must be renewed — limits blast radius of a compromise.

```bash
# Start Vault in dev mode (lab only)
docker run --rm -d --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  hashicorp/vault:latest

# Access Vault UI: http://localhost:8200 (token: root)

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

# Store EMS secrets
vault kv put secret/ems \
  db_password=SBI_EMS_Secure_2024 \
  jwt_secret=$(openssl rand -hex 32)

# Retrieve
vault kv get -field=db_password secret/ems
```

## 4.5 Node.js + Vault Integration

```bash
npm install node-vault
```

```javascript
// src/config/vault.js — fetch secrets from Vault at startup
const vault = require('node-vault');

const client = vault({
  apiVersion: 'v1',
  endpoint:   process.env.VAULT_ADDR || 'http://localhost:8200',
  token:      process.env.VAULT_TOKEN,
});

exports.loadSecrets = async () => {
  const { data } = await client.read('secret/data/ems');
  process.env.DB_PASSWORD  = data.data.db_password;
  process.env.JWT_SECRET   = data.data.jwt_secret;
  console.log('Secrets loaded from Vault');
};

// app.js — load secrets before starting the server
const { loadSecrets } = require('./config/vault');
loadSecrets().then(() => {
  app.listen(process.env.PORT || 3000);
});
```

> **Banking Best Practices for Secrets:**
> 1. Never commit secrets to version control — use pre-commit hooks.
> 2. Rotate secrets regularly — Vault automates this for databases.
> 3. Use separate secrets per environment (dev / staging / prod).
> 4. Audit who accesses which secrets — Vault provides this log.
> 5. Use short-lived tokens — limit blast radius of credential theft.

---

# Module 5: CI/CD Security Integration
`4:45 – 5:15` · Pipeline Gates · SAST in CI · DAST in CD · Fail Fast · GitHub Actions

Embedding security tools into the CI/CD pipeline transforms security from a periodic audit into a continuous, automated process. Every code push triggers a security scan; a failed gate blocks deployment. This is the operational heart of DevSecOps.

## 5.1 The Secure Pipeline Model

| Stage | Gate | Tool |
|---|---|---|
| Pre-commit | Block secrets before they reach git | detect-secrets hook |
| Build (CI) | Block Critical vulnerabilities in code | SonarQube Quality Gate |
| Deploy (CD) | Block High-risk vulnerabilities at runtime | OWASP ZAP DAST |

## 5.2 GitHub Actions Pipeline for EMS

```yaml
# .github/workflows/devsecops.yml
name: EMS DevSecOps Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0

    - name: Set up Node.js 20
      uses: actions/setup-node@v3
      with:
        node-version: '20'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci   # reproducible install — always use ci, not install

    - name: Detect secrets
      run: |
        pip install detect-secrets
        detect-secrets scan . > /tmp/secrets-baseline.json

    - name: Run tests with coverage
      run: npm test -- --coverage

    - name: SAST — SonarQube scan
      env:
        SONAR_TOKEN:    ${{ secrets.SONAR_TOKEN }}
        SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
      run: |
        npx sonar-scanner \
          -Dsonar.token=$SONAR_TOKEN \
          -Dsonar.qualitygate.wait=true \
          -Dsonar.qualitygate.timeout=300

    - name: Build Docker image
      run: docker build -t ems:${{ github.sha }} .

    - name: Container scan with Trivy
      run: |
        trivy image --severity HIGH,CRITICAL \
          --exit-code 1 \
          ems:${{ github.sha }}

    - name: Start EMS for DAST
      run: |
        docker run -d --name ems-test \
          -p 3000:3000 \
          -e JWT_SECRET=${{ secrets.JWT_SECRET }} \
          -e DB_PASSWORD=${{ secrets.DB_PASSWORD_TEST }} \
          ems:${{ github.sha }}
        sleep 15   # wait for Express startup (faster than Spring Boot)

    - name: DAST — ZAP API scan
      run: |
        docker run --network=host \
          ghcr.io/zaproxy/zaproxy:stable \
          zap-api-scan.py \
          -t http://localhost:3000/api-docs.json \
          -f openapi \
          -r zap-report.html

    - name: Upload ZAP report
      uses: actions/upload-artifact@v3
      with:
        name: zap-report
        path: zap-report.html
```

## 5.3 Quality Gate Configuration

| Condition | Threshold |
|---|---|
| New Blocker Issues | = 0 |
| New Critical Issues | = 0 |
| New Coverage on New Code | >= 70% |
| New Duplicated Lines | <= 3% |
| Security Hotspots Reviewed | = 100% |

## 5.4 Day 1 Summary

| Module | Key Takeaway | EMS Application |
|---|---|---|
| Secure Coding | OWASP Top 10 in Node.js/Express; validation; safe error handling | Added `authorize` middleware on salary; fixed `errorHandler` |
| SAST | SonarQube taint analysis; Quality Gates; IDE integration | Scanned EMS; fixed hardcoded JWT secret; fixed missing auth |
| DAST | ZAP active scan; API scanning via OpenAPI; alert triage | Scanned running EMS; added `helmet` headers; fixed CORS |
| Secrets Mgmt | Never commit secrets; detect-secrets hook; Vault basics | Moved JWT secret to `.env`/Vault; added startup guard |
| CI/CD | Pipeline gates at pre-commit, build, and deploy stages | Reviewed full GitHub Actions pipeline for EMS |

> **Day 2 Preview:** Tomorrow we move to infrastructure security — Container Security (hardening Docker images, scanning with Trivy), Infrastructure as Code Security (Terraform misconfiguration scanning with Checkov), and an end-to-end capstone lab that wires everything together into a single automated pipeline.

---

*Confidential — For Training Purposes Only*
*DevSecOps Intermediate · State Bank of India · Technology Training Programme*
