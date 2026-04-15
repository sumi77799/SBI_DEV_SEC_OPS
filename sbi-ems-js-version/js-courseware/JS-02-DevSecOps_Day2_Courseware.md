# DevSecOps — Intermediate | Participant Courseware
## DAY 2
**Container Security · IaC Security · Integrated DevSecOps Pipeline · Banking Case Studies**

*Project: SBI Employee Management System (EMS) — Node.js / Express.js*
*State Bank of India — Technology Training Programme*

---

## Day 2 Schedule

| Time | Session | Topics |
|---|---|---|
| 10:30 – 11:30 | **Container Security** | Docker hardening, image scanning, runtime security, Kubernetes basics |
| 11:30 – 12:15 | **Lab 3: Container Scan** | Trivy scan of EMS image, Dockerfile fix, hardened image rebuild |
| 12:15 – 12:30 | Break | — |
| 12:30 – 1:30 | **IaC Security** | Terraform security, misconfig patterns, Checkov policy scanning |
| 1:30 – 2:15 | **Lab 4: IaC Scan** | Checkov scan of EMS Terraform, fix misconfigs, policy-as-code |
| 2:15 – 3:00 | Lunch | — |
| 3:00 – 4:00 | **Integrated DevSecOps Pipeline** | End-to-end pipeline; all gates combined; shift-left metrics |
| 4:00 – 5:00 | **Comprehensive Capstone Lab** | Full pipeline run: code → SAST → container scan → IaC → DAST |
| 5:00 – 5:30 | **Case Studies + Q&A** | Real banking security incidents and lessons learned |

---

# Module 6: Container Security
`10:30 – 11:30` · Docker Hardening · Image Scanning · Trivy · Runtime Security · Kubernetes RBAC

Containers have become the standard deployment unit for modern banking applications. The EMS application is packaged as a Docker container. While containers provide consistency and portability, they also introduce a new attack surface that requires dedicated security controls at every layer: the image, the runtime, and the orchestration platform.

## 6.1 The Container Attack Surface

Security risks in containers exist at four distinct layers. An attacker who gains access at any layer can potentially escalate to the others:

| Layer | Risk | EMS Example |
|---|---|---|
| Base image | Outdated OS packages with known CVEs; running as root | `node:20` includes 400+ OS packages, many with CVEs |
| Application dependencies | npm packages with known vulnerabilities | `express`, `sequelize`, `jsonwebtoken` — all scanned by Trivy |
| Container runtime | Excessive Linux capabilities; privileged mode; host namespace access | EMS container needs no capabilities — drop all by default |
| Orchestration (Kubernetes) | Overly permissive RBAC; exposed API server; default service accounts | EMS pod should run with a restricted ServiceAccount |

## 6.2 Writing a Secure Dockerfile for EMS

The default Dockerfile many developers write for a Node.js application is insecure in multiple ways. Here is the before and after for EMS.

### Insecure Dockerfile (Common Mistakes)

```dockerfile
# INSECURE — do not use this
FROM node:20           # full Node.js image — 1 GB+ with build tools, compilers
WORKDIR /app
COPY . .
RUN npm install        # installs devDependencies too — unnecessary attack surface
EXPOSE 3000
CMD ["node", "src/app.js"]

# Problems:
# 1. Running as root (uid 0)
# 2. Full node image — massive attack surface
# 3. devDependencies installed — testing tools, linters not needed at runtime
# 4. .env file may be copied in (secrets exposure risk)
# 5. No health check defined
# 6. No .dockerignore — copies node_modules, .git, .env
```

### Hardened Dockerfile for EMS (Best Practice)

```dockerfile
# Stage 1 — Install dependencies (includes devDependencies for build/test)
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
# Install ALL dependencies (including dev) for any build steps
RUN npm ci

# Stage 2 — Runtime (production dependencies only)
FROM node:20-alpine AS runtime

# Create non-root user — NEVER run as root
RUN addgroup -S emsgroup && adduser -S emsuser -G emsgroup

WORKDIR /app

# Copy only package files first — cache this layer
COPY package*.json ./

# Install ONLY production dependencies — no dev tools in the image
RUN npm ci --omit=dev && npm cache clean --force

# Copy application source — not node_modules, not .env, not .git
COPY --chown=emsuser:emsgroup src/ ./src/

# Switch to non-root user
USER emsuser

# Expose only the application port
EXPOSE 3000

# Health check — Kubernetes uses this to determine readiness
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

# Use node directly — not npm start (avoids npm as PID 1)
CMD ["node", "src/app.js"]
```

```
# .dockerignore — CRITICAL: prevent secrets and unnecessary files entering the image
.env
.env.*
.git
.gitignore
node_modules
coverage
*.test.js
*.spec.js
README.md
Dockerfile*
docker-compose*
terraform/
.secrets.baseline
```

> **Why Non-Root Matters:** If an attacker exploits a vulnerability in EMS (e.g. a path traversal bug), running as root gives them root on the host — they can read `/etc/shadow`, modify the host filesystem, or escape the container. Running as a non-root user (uid 1000+) limits the blast radius to the container's own files.

## 6.3 Multi-Stage Builds and Image Minimization

The multi-stage Dockerfile above separates the dependency installation layer from the runtime layer, and uses `--omit=dev` to exclude test and build tools from the final image:

| Image | Size |
|---|---|
| `node:20` (base) | ~1.1 GB, full Debian, build tools, Python |
| `node:20-alpine` (base) | ~180 MB, Alpine Linux, minimal OS |
| EMS single-stage build | ~320 MB (base + all deps including devDeps) |
| EMS multi-stage `--omit=dev` | ~210 MB (prod deps + source only) |
| Distroless Node.js (advanced) | ~150 MB — no shell, no package manager at all |

## 6.4 Trivy — Container Vulnerability Scanning

Trivy is a comprehensive security scanner for containers. It scans OS packages, language-specific packages (npm), and IaC files for known CVEs and misconfigurations.

```bash
# Basic scan
trivy image ems:latest

# Scan with severity filter — only HIGH and CRITICAL
trivy image --severity HIGH,CRITICAL ems:latest

# Exit code 1 if any CRITICAL found — use in CI pipelines
trivy image --severity CRITICAL --exit-code 1 ems:latest

# Generate SARIF report for GitHub Security tab
trivy image --format sarif --output trivy-results.sarif ems:latest

# Scan the Dockerfile itself for misconfigurations
trivy config ./Dockerfile

# Scan the project filesystem for npm dependency CVEs
trivy fs --security-checks vuln ./ems
```

## 6.5 Understanding Trivy Output

```
ems:latest (alpine 3.18.4)
================================
Total: 2 (HIGH: 1, CRITICAL: 1)

Library    Vulnerability  Severity  Installed  Fixed     Title
---------- -------------- --------- ---------- --------- ----
libssl3    CVE-2023-5678  CRITICAL  3.1.3-r0   3.1.4-r0  OpenSSL heap overflow
musl       CVE-2023-1234  HIGH      1.2.4-r0   1.2.4-r1  musl libc buffer overflow

Node.js (package-lock.json)
================================
Total: 1 (HIGH: 1)

Library          Vulnerability  Severity  Version  Fixed    Title
---------------- -------------- --------- -------- -------- ----
jsonwebtoken     CVE-2024-xxxx  HIGH      8.5.1    9.0.0    JWT algorithm confusion attack
```

Trivy output groups findings by component type. For EMS you will see:

- **OS packages (alpine):** Findings from the Alpine Linux base image packages.
- **Node.js (package-lock.json):** Findings from Express, Sequelize, and transitive npm dependencies.
- **Secrets:** Any accidentally included `.env` files or credential files.

> **Trivy in CI/CD:** In the pipeline, Trivy runs after the Docker build and before deployment. `--exit-code 1` causes the pipeline to fail on any CRITICAL finding. This ensures no critically vulnerable container image is ever deployed to any environment.

## 6.6 Docker Runtime Security

Even with a hardened image, the container must be started with security constraints:

```yaml
# docker-compose.yml — EMS with runtime security constraints
services:
  ems:
    image: ems:latest
    ports:
      - "3000:3000"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - DB_PASSWORD=${DB_PASSWORD}
    security_opt:
      - no-new-privileges:true   # prevents privilege escalation
    read_only: true              # root filesystem is read-only
    tmpfs:
      - /tmp                     # writable temp space if needed
    cap_drop:
      - ALL                      # drop ALL Linux capabilities
    cap_add: []                  # add NONE back
    mem_limit: 512m
    cpus: "1.0"
    user: "1000:1000"            # run as non-root
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

# Lab 3: Container Security Scan
`11:30 – 12:15` · Build EMS image · Trivy scan · Fix Dockerfile · Rebuild · Re-scan

> **Lab Objective:** Build the insecure EMS Docker image, scan it with Trivy to identify vulnerabilities, apply Dockerfile hardening (multi-stage build + non-root user + `--omit=dev`), rebuild, and re-scan to confirm vulnerability count drops.

## Step 1 — Build the Insecure EMS Image

```bash
docker build -f Dockerfile.insecure -t ems:insecure .
```

## Step 2 — Scan the Insecure Image

```bash
trivy image --severity HIGH,CRITICAL ems:insecure
```

Note the total number of HIGH and CRITICAL findings: `_______`

Identify the top 3 packages with the most Critical findings.

## Step 3 — Inspect the Dockerfile

Open `Dockerfile.insecure` in VS Code. List all the security problems you can spot:

```
1. _________________________________________________
2. _________________________________________________
3. _________________________________________________
4. _________________________________________________
```

## Step 4 — Apply the Hardened Dockerfile

The hardened Dockerfile is at `ems/Dockerfile.secure`. Review it — confirm `node:20-alpine` base, `--omit=dev` install, non-root user, `.dockerignore`, `HEALTHCHECK`. Build it:

```bash
docker build -f Dockerfile.secure -t ems:secure .
```

## Step 5 — Re-scan the Hardened Image

```bash
trivy image --severity HIGH,CRITICAL ems:secure
```

New total: `_______` (should be significantly lower)

Compare image sizes:

```bash
docker images | grep ems
```

## Step 6 — Scan the Dockerfile for Misconfigs

```bash
trivy config ./Dockerfile.secure
```

Are there any remaining misconfigurations flagged? Note them.

> **Discussion:** Why did the vulnerability count drop? It is not because we 'fixed' CVEs — it is because we switched from `node:20` (Debian full) to `node:20-alpine` (minimal Alpine) and excluded `devDependencies`. Reducing attack surface is as important as patching.

---

# Module 7: Infrastructure as Code Security
`12:30 – 1:30` · Terraform Misconfigurations · Checkov · Policy-as-Code · Drift Detection

Infrastructure as Code (IaC) means defining servers, networks, databases, and security controls in code files rather than through manual console clicks. For banking environments deploying on cloud (AWS/Azure/GCP) or private cloud, IaC is the primary way infrastructure is provisioned. A misconfigured Terraform file can create an open S3 bucket, a publicly accessible database, or a VM with no firewall — at the speed of automation.

## 7.1 Why IaC Security is Critical in Banking

The Capital One breach of 2019 exposed 100 million customer records. Root cause: a misconfigured AWS Web Application Firewall created through manual console configuration. Had IaC been used with policy scanning, the misconfiguration would have been caught before deployment. Key IaC security principles:

- **Immutable infrastructure:** never modify running infrastructure manually — all changes through IaC.
- Every IaC change goes through version control and code review — just like application code.
- Policy scanning (Checkov) runs on every IaC change before it is applied.
- **Drift detection:** detect when actual infrastructure diverges from the IaC definition.

## 7.2 Common IaC Misconfigurations

### Misconfiguration 1: Database Publicly Accessible

```hcl
# INSECURE — RDS instance accessible from the internet
resource "aws_db_instance" "ems_mysql" {
  engine              = "mysql"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = "SBI_EMS_DB_2024!"   # hardcoded!
  publicly_accessible = true                  # CRITICAL MISCONFIGURATION
  skip_final_snapshot = true
}

# SECURE — database only accessible from within the VPC
resource "aws_db_instance" "ems_mysql" {
  engine                 = "mysql"
  instance_class         = "db.t3.medium"
  username               = "admin"
  password               = var.db_password    # from Vault/variable
  publicly_accessible    = false              # not internet-accessible
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  storage_encrypted      = true               # encrypt at rest
  deletion_protection    = true               # prevent accidental deletion
  skip_final_snapshot    = false              # take snapshot on deletion
}
```

### Misconfiguration 2: S3 Bucket Publicly Accessible

```hcl
# INSECURE — public S3 bucket
resource "aws_s3_bucket_acl" "ems_reports_acl" {
  bucket = aws_s3_bucket.ems_reports.id
  acl    = "public-read"  # CRITICAL — all employee reports visible to internet
}

# SECURE — block all public access
resource "aws_s3_bucket_public_access_block" "ems_reports" {
  bucket                  = aws_s3_bucket.ems_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ems_enc" {
  bucket = aws_s3_bucket.ems_reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

### Misconfiguration 3: Security Group — All Traffic Allowed

```hcl
# INSECURE — allows ALL inbound traffic
resource "aws_security_group" "ems_sg" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # allows all traffic from internet
  }
}

# SECURE — allow only port 443 from internet; port 3000 from load balancer only
resource "aws_security_group" "ems_sg" {
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description     = "App port from load balancer only"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]  # NOT from internet
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## 7.3 Checkov — Policy Scanning for IaC

Checkov is an open-source static analysis tool for Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles. It runs over 1,000 built-in security policies aligned with CIS benchmarks, HIPAA, PCI-DSS, and SOC 2.

```bash
# Scan the EMS Terraform directory
checkov -d ./terraform/ems

# Scan a specific file
checkov -f ./terraform/ems/main.tf

# Scan and output JUnit XML for CI pipeline integration
checkov -d ./terraform/ems --output junitxml > checkov-results.xml

# Show only FAILED checks
checkov -d ./terraform/ems --compact

# Scan against specific compliance framework
checkov -d ./terraform/ems --framework terraform --check CKV_AWS_*
```

## 7.4 Understanding Checkov Output

```
Passed checks: 34, Failed checks: 6, Skipped checks: 0

Check: CKV_AWS_17: "Ensure all data stored in the RDS instance is not publicly accessible"
  FAILED for resource: aws_db_instance.ems_mysql
  File: /terraform/ems/main.tf:12-28

  Code:
    12 | resource "aws_db_instance" "ems_mysql" {
    ...
    22 |   publicly_accessible = true   <-- this line causes the failure
    ...
    28 | }
```

## 7.5 Policy-as-Code with Checkov Custom Policies

Checkov allows you to write custom policies for organisation-specific rules. For SBI's EMS deployment, a custom policy enforces that all RDS instances must use Multi-AZ (required by RBI's BCM guidelines):

```python
# custom_policies/CKV_SBI_001.py
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class DBMultiAZCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instance uses Multi-AZ (RBI BCM requirement)"
        id   = "CKV_SBI_001"
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        supported_resources = ["aws_db_instance"]
        super().__init__(name=name, id=id,
                         categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        multi_az = conf.get("multi_az", [False])[0]
        if multi_az:
            return CheckResult.PASSED
        return CheckResult.FAILED

check = DBMultiAZCheck()
```

```bash
# Run with custom policy
checkov -d ./terraform/ems --external-checks-dir ./custom_policies
```

## 7.6 Terraform Security Best Practices for EMS

| Practice | Implementation |
|---|---|
| Use variables, not literals | `var.db_password`, not `"password123"` |
| Store state in encrypted backend | S3 + KMS, not local `terraform.tfstate` |
| Enable versioning on state bucket | S3 versioning for audit trail and rollback |
| Use least-privilege IAM roles | EMS task role only has access to its own RDS, S3, secrets |
| Encrypt all data at rest | `storage_encrypted=true` on RDS; SSE-KMS on S3 |
| Enable VPC flow logs | Capture all network traffic for audit |
| Tag all resources | `team=devops`, `environment=prod`, `project=ems`, `owner=sbi-team` |

---

# Lab 4: IaC Security with Checkov
`1:30 – 2:15` · Checkov scan of EMS Terraform · Fix misconfigurations · Custom policy

> **Lab Objective:** Run Checkov against the EMS Terraform configuration, identify and fix the three critical misconfigurations (public DB, open security group, unencrypted storage), and write a simple custom SBI policy.

## Step 1 — Explore the EMS Terraform

Navigate to the `terraform/ems/` folder in VS Code. Open `main.tf`. Identify the `aws_db_instance`, `aws_security_group`, and `aws_s3_bucket` resources. Without running any tool — can you spot the misconfigurations by reading the code?

## Step 2 — Run Checkov Scan

```bash
cd terraform/ems
checkov -d . --compact
```

Note the number of FAILED checks: `_______`

```
Failed Check 1: ___________________________________
Failed Check 2: ___________________________________
Failed Check 3: ___________________________________
Failed Check 4: ___________________________________
```

## Step 3 — Fix the Misconfigurations

Apply the patterns from Module 7 to `main.tf`:

- Set `publicly_accessible = false` on the RDS instance.
- Add `storage_encrypted = true` on the RDS instance.
- Add `aws_s3_bucket_public_access_block` with all four block options set to `true`.
- Restrict the security group ingress to specific ports only (note: EMS runs on port 3000, not 8080).

## Step 4 — Re-scan

```bash
checkov -d . --compact
```

New FAILED count: `_______` (should be 0 or close to 0)

## Step 5 — Write a Custom Policy

Create `custom_policies/CKV_SBI_001.py` with the Multi-AZ check from Module 7. Run with:

```bash
checkov -d . --external-checks-dir ../custom_policies --compact
```

Does the EMS RDS resource pass or fail your custom `CKV_SBI_001` check? If it fails, add `multi_az = true` to the `aws_db_instance` resource and re-run.

> **Real-World Relevance:** RBI's Business Continuity Management guidelines (Annex 7 of the Master Direction on IT) require that critical banking applications have multi-AZ or equivalent high availability. The custom Checkov policy you just wrote enforces this at the IaC level — automatically, on every deployment.

---

# Module 8: The Integrated DevSecOps Pipeline
`3:00 – 4:00` · End-to-End · All Gates · Metrics · Shift-Left Maturity Model

The goal of DevSecOps is not a collection of individual security tools — it is a continuous, automated security process woven into every stage of software delivery. This module brings together everything from Day 1 and Day 2 into a single, coherent pipeline for EMS.

## 8.1 The EMS Complete Security Pipeline

| Stage | Tool / Control | Pass Condition |
|---|---|---|
| 1. Pre-commit | detect-secrets hook | No secrets in staged files |
| 2. Commit (CI trigger) | SonarQube SAST | Quality Gate passes (0 Critical/Blocker) |
| 3. Build | `npm ci` + `npm test` | All unit tests pass (including security tests) |
| 4. Container build | Trivy image scan | 0 CRITICAL CVEs in image |
| 5. IaC change | Checkov scan | 0 FAILED checks (or suppressed with justification) |
| 6. Staging deploy | OWASP ZAP DAST | 0 High-risk alerts |
| 7. Production deploy | Manual approval | Security team sign-off |

## 8.2 Complete Pipeline YAML — EMS

```yaml
# .github/workflows/devsecops-full.yml
name: EMS Full DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  IMAGE_NAME: sbi-ems
  IMAGE_TAG: ${{ github.sha }}

jobs:
  # ── STAGE 1: SAST ────────────────────────────────────────────
  sast:
    name: SAST — Code Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with: { fetch-depth: 0 }

      - uses: actions/setup-node@v3
        with: { node-version: "20", cache: "npm" }

      - name: Install dependencies
        run: npm ci

      - name: Detect secrets
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files .

      - name: Semgrep scan
        run: |
          pip install semgrep
          semgrep --config=p/owasp-top-ten --config=p/javascript --error ./src

      - name: Run tests with coverage
        run: npm test -- --coverage

      - name: SonarQube — Quality Gate
        env:
          SONAR_TOKEN:    ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        run: |
          npx sonar-scanner \
            -Dsonar.token=$SONAR_TOKEN \
            -Dsonar.qualitygate.wait=true

  # ── STAGE 2: IaC SCAN ────────────────────────────────────────
  iac-scan:
    name: IaC — Checkov Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Checkov IaC scan
        run: |
          pip install checkov
          checkov -d terraform/ems \
            --external-checks-dir custom_policies \
            --output junitxml > checkov-results.xml

  # ── STAGE 3: BUILD + CONTAINER SCAN ─────────────────────────
  build-and-scan:
    name: Build + Container Scan
    needs: [sast, iac-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -f Dockerfile.secure -t $IMAGE_NAME:$IMAGE_TAG .

      - name: Trivy — container scan
        run: |
          trivy image \
            --severity HIGH,CRITICAL \
            --exit-code 1 \
            --format sarif \
            --output trivy-results.sarif \
            $IMAGE_NAME:$IMAGE_TAG

      - name: Push to registry (only on main)
        if: github.ref == 'refs/heads/main'
        run: |
          docker tag $IMAGE_NAME:$IMAGE_TAG \
            registry.sbi.internal/$IMAGE_NAME:$IMAGE_TAG
          docker push registry.sbi.internal/$IMAGE_NAME:$IMAGE_TAG

  # ── STAGE 4: DAST ────────────────────────────────────────────
  dast:
    name: DAST — ZAP API Scan
    needs: build-and-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3

      - name: Start EMS (staging)
        run: |
          docker run -d --name ems-staging \
            -p 3000:3000 \
            -e JWT_SECRET=${{ secrets.JWT_SECRET }} \
            -e NODE_ENV=staging \
            registry.sbi.internal/$IMAGE_NAME:$IMAGE_TAG
          sleep 15   # Node.js starts much faster than Spring Boot

      - name: ZAP API Scan
        run: |
          docker run --network=host \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-api-scan.py \
            -t http://localhost:3000/api-docs.json \
            -f openapi -r zap-report.html \
            -l WARN

      - name: Upload ZAP report
        uses: actions/upload-artifact@v3
        with: { name: zap-dast-report, path: zap-report.html }
```

## 8.3 DevSecOps Maturity Model

| Level | Characteristics | EMS Target |
|---|---|---|
| Level 1 — Ad hoc | Manual security reviews; no tooling in pipeline | Starting point for most legacy banking apps |
| Level 2 — Defined | SAST tool in place; developers aware of findings | SonarQube integrated; Quality Gate enforced |
| Level 3 — Consistent | SAST + DAST automated; secrets management active | Days 1+2 lab state — all tools in CI/CD |
| Level 4 — Quantified | Security metrics tracked; SLAs on remediation time | MTTR for security findings tracked in Jira |
| Level 5 — Optimizing | Threat modelling; chaos engineering; red team | Target state for banking security programmes |

## 8.4 Security Metrics That Matter

| Metric | What it measures |
|---|---|
| Mean Time to Remediate (MTTR) — Critical | How quickly critical vulnerabilities are fixed after discovery |
| Vulnerability escape rate | % of vulnerabilities found in production vs caught in pipeline |
| Quality Gate pass rate | % of builds passing security gate — signals developer adoption |
| New vs total technical debt | Are we paying down security debt or accumulating it? |
| Container base image age | Days since base image was last updated — older = more CVEs |
| Secrets detected pre-commit | Count of secrets caught by hooks (lower is better over time) |

---

# Capstone Lab: End-to-End DevSecOps on EMS
`4:00 – 5:00` · Code change → SAST → Container Scan → IaC Scan → DAST → Verify all gates

> **Lab Objective:** Simulate a real developer workflow: make a code change to EMS that introduces a security vulnerability, watch the pipeline catch it, fix it, and push again to watch all gates pass. This exercise ties together every tool from both days.

## Scenario

The EMS development team has received a new requirement: add a department search endpoint. A developer has implemented it using string interpolation in a raw SQL query (introducing SQL injection). Your job is to:

1. Run the full security pipeline against this change.
2. Identify the vulnerability using SAST.
3. Confirm it is exploitable using DAST.
4. Fix the code.
5. Rebuild the Docker image and rescan with Trivy.
6. Confirm all gates pass.

## Step 1 — Introduce the Vulnerability

Open `src/routes/employeeRoutes.js` and add:

```javascript
// NEW ENDPOINT — vulnerable to SQL injection
router.get('/search', authenticate, async (req, res, next) => {
  try {
    const { dept } = req.query;
    // VULNERABLE — raw SQL with string interpolation
    const [results] = await sequelize.query(
      `SELECT * FROM Employees JOIN Departments ON Employees.departmentId = Departments.id
       WHERE Departments.name = '${dept}'`   // injection point
    );
    res.json(results);
  } catch (err) {
    next(err);
  }
});
```

Commit:

```bash
git add . && git commit -m "feat: add department search endpoint"
```

## Step 2 — Run SAST

```bash
npm test -- --coverage
npx sonar-scanner \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

Open the SonarQube dashboard. Find the new Critical issue on the search endpoint. Read the taint analysis — where does the user input enter? Where is the unsafe query built?

## Step 3 — Confirm with DAST

1. Start EMS: `docker compose up -d`
2. In ZAP, Spider and Active Scan the running EMS.
3. Check for SQL injection alerts on `/api/v1/employees/search`.
4. Use ZAP's Fuzzer — right-click the search request > **Fuzz** > add payload: `' OR '1'='1`

## Step 4 — Fix the Vulnerability

```javascript
// FIXED — using Sequelize parameterized query (safe)
router.get('/search', authenticate,
  query('dept').notEmpty().isLength({ max: 100 }),
  validate,
  async (req, res, next) => {
    try {
      const { dept } = req.query;
      const results = await Employee.findAll({
        include: [{
          model: Department,
          where: { name: dept },  // Sequelize uses parameterized WHERE
        }],
      });
      res.json(results);
    } catch (err) {
      next(err);
    }
  }
);
```

Commit the fix and re-run the SAST scan to confirm it passes.

## Step 5 — Rebuild Container and Re-scan

```bash
docker build -f Dockerfile.secure -t ems:capstone .
trivy image --severity HIGH,CRITICAL --exit-code 1 ems:capstone
```

Confirm Trivy passes.

## Step 6 — Run IaC Scan

```bash
checkov -d terraform/ems --compact
```

Confirm: 0 FAILED checks.

## Step 7 — Final DAST Verification

```bash
docker compose up -d
```

Re-run ZAP Active Scan. Confirm: the SQL injection alert on `/search` is gone.

> **Congratulations:** You have completed a full DevSecOps cycle — introduced a vulnerability, caught it with SAST, confirmed it with DAST, fixed it at the code level, verified the fix across container and IaC layers, and confirmed clean DAST results. This is the DevSecOps workflow.

---

# Module 9: Banking Case Studies + Q&A
`5:00 – 5:30` · Real Incidents · Lessons Learned · RBI Compliance Mapping

## Case Study 1 — SWIFT Banking Fraud (Bangladesh Bank, 2016)

- **What happened:** Attackers gained access to the Bangladesh Bank's SWIFT terminal, modified legitimate transaction requests, and transferred $81 million to fraudulent accounts in the Philippines.
- **Root DevSecOps cause:** Malware on SWIFT terminals (no container/endpoint security); hardcoded credentials in legacy systems (no secrets management); no anomaly detection on outbound transactions (no monitoring/logging).
- **How tools from this training would have helped:**

```
- Secrets management (Vault):  rotating SWIFT credentials automatically
- Container security:           isolating SWIFT terminal software
- SAST:                         detecting hardcoded credentials in SWIFT integration code
- Monitoring:                   anomaly detection on transaction amounts/patterns
```

## Case Study 2 — Critical npm Dependency Vulnerability (2022–2023)

- **What happened:** Several widely-used npm packages — including popular middleware and utility libraries — had critical CVEs published (prototype pollution, RCE via deserialization). Node.js banking applications using these transitive dependencies were vulnerable for weeks until patched.
- **Root DevSecOps cause:** No container/dependency scanning (Trivy would have flagged the CVE within 24 hours of NVD publication); no automated `npm audit` in CI pipelines.
- **How Trivy would have caught it:**

```
trivy image ems:vulnerable-era

# Output:
# CVE-2022-xxxx  CRITICAL  some-npm-package  2.3.1  Fixed: 2.3.2
# Remote Code Execution via prototype pollution
# CVSS: 9.8

# --exit-code 1 would have blocked deployment automatically
```

## Case Study 3 — Exposed S3 Bucket at an NBFC (India, 2023)

- **What happened:** An NBFC's cloud team created an S3 bucket for customer KYC documents and accidentally set it to `public-read` during testing. The configuration was never reverted before the bucket was used in production.
- **Data exposed:** 2.3 lakh customer KYC documents including Aadhaar numbers, PAN cards, and bank statements.
- **Root DevSecOps cause:** IaC not used (manual console configuration); no IaC scanning.
- **How Checkov would have prevented it:**

```
# If IaC had been used and Checkov had run:
# Check: CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled"
#   FAILED for resource: aws_s3_bucket.kyc_documents
#
# Pipeline would have blocked deployment before the bucket went live.
```

## RBI Compliance Mapping

| RBI Requirement | Section | DevSecOps Control |
|---|---|---|
| Secure Software Development Lifecycle | 6.3 | SAST (SonarQube), DAST (ZAP), peer code review |
| Vulnerability management | 6.4 | Trivy CVE scanning, `npm audit`, OWASP Dependency-Check |
| Secrets and credential management | 6.5 | HashiCorp Vault, detect-secrets, `dotenv`, no hardcoded secrets |
| Audit logging for sensitive data access | 7.2 | Winston audit logger middleware, structured JSON logs, SIEM integration |
| Change management with security review | 8.1 | CI/CD pipeline gates, security sign-off before production |
| Business continuity (Multi-AZ) | Annex 7 | Custom Checkov policy (CKV_SBI_001) |
| Infrastructure security baseline | 6.6 | Checkov CIS benchmark checks, IaC-enforced configuration |

## Key Takeaways — Both Days

| Day | Module | The One Thing to Remember |
|---|---|---|
| Day 1 | Secure Coding | Write security in from line 1 — `authorize` middleware, `express-validator`, `bcrypt`, safe `errorHandler` |
| Day 1 | SAST | SonarQube finds what you cannot see — run it on every commit; fix Critical before merging |
| Day 1 | DAST | The running app is the ground truth — ZAP finds what SAST cannot (headers, runtime config) |
| Day 1 | Secrets | A secret in git is a secret forever — use detect-secrets hooks, `dotenv`, and Vault |
| Day 1 | CI/CD | Automate the gates — a gate only you manually run is a gate that gets skipped |
| Day 2 | Containers | Non-root + `node:alpine` + `--omit=dev` + Trivy scan = 90% of container security |
| Day 2 | IaC | Every infra change through Terraform; every Terraform through Checkov |
| Day 2 | Pipeline | DevSecOps is a culture before it is a toolchain — fast feedback, shared ownership |

## Next Steps for Your Team

1. Set up SonarQube in your internal CI/CD (Jenkins/GitLab/GitHub Actions) this week.
2. Add detect-secrets pre-commit hooks to all active repositories.
3. Add Trivy to your container build pipeline — even if exit-code 0 initially.
4. Run Checkov on your existing Terraform — treat it as a security audit.
5. Schedule a quarterly DAST scan on all externally-facing applications.
6. Present the RBI compliance mapping to your CISO — this programme addresses real regulatory requirements.

---

*Confidential — For Training Purposes Only*
*DevSecOps Intermediate · State Bank of India · Technology Training Programme*
