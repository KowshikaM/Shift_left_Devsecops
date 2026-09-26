# Secure DevOps Pipeline — Shift-Left Security

A local, demo-ready DevSecOps control center that turns a GitHub push into an enforced security decision:

**GitHub → Jenkins → Application Tests → Semgrep/Gitleaks → Docker build → Trivy → OPA/Conftest → Security Gate → Dashboard → Docker Hub → kind/minikube**

A failed build is retained in dashboard history. Only a passing build on `main` may push or deploy. AI remediation is human-triggered, validated by Jenkins, and opened as a PR; it never merges or deploys.

## Current implementation

- Jenkins Pipeline designed for a **Windows Jenkins agent**.
- Dashboard service runs in Docker at **http://localhost:2001**.
- Persistent dashboard history uses the existing SQLite volume from the supplied project scaffold. This keeps the one-day local demo reliable; MongoDB/RBAC are intentionally not introduced into this revision because they would replace the working dashboard rather than make the core demo safer.
- Real containerized scanners: Semgrep, Gitleaks, Trivy and OPA/Conftest.
- Central gate blocks on CRITICAL/HIGH findings and on missing/invalid scanner evidence or scanner execution errors.
- Docker Hub receives only an immutable build-number tag; `latest` is not pushed or deployed.
- Kubernetes deployment uses the exact registry image tag produced by a passing `main` build; feature and AI-remediation branches cannot push or deploy.
- Groq is the only AI provider. The model is selected with `GROQ_MODEL`; the API key is stored as the Jenkins credential `groq-api-key`.
- Only LOW and MEDIUM non-secret findings are AI-eligible. HIGH, CRITICAL, Gitleaks, and secret-like findings require manual review.
- Python controls the AI workflow: scanner baseline, structured proposal validation, one-file unified patch, project tests, complete rescan, before/after comparison, rollback on failure, and isolated commit on success.
- The AI workflow creates a branch and PR only after validation. It never merges or deploys. The normal main pipeline gate still controls deployment.
- Human review/merge remains mandatory.
- Manual remediation remains available when AI is unavailable.

Groq uses its OpenAI-compatible Chat Completions endpoint at `https://api.groq.com/openai/v1`. The key is provided only through Jenkins credentials and is never written to the repository.

## Project structure

```text
secure-devops-pipeline/
├── app/                         # intentionally vulnerable demo application
├── Dockerfile                  # intentionally insecure first-run image
├── k8s/                        # intentionally insecure first-run manifest
├── policy/                     # Dockerfile + Kubernetes OPA policies
├── scripts/
│   ├── evaluate_gate.py        # centralized security gate
│   ├── publish_to_dashboard.py # persistent dashboard ingestion
│   ├── generate_dashboard.py   # Jenkins archived HTML report
│   ├── create_remediation_tickets.py
│   ├── classify_remediations.py # writes this build's eligibility report
│   ├── remediation_policy.py   # import shim to shared dashboard policy
│   ├── ai_remediation_agent.py # deterministic controller and validation tools
│   ├── groq_client.py          # Groq-only structured proposal client
│   ├── ai_fix_single.py        # compatibility entry point
│   └── create_ai_pr.py         # creates PR only after validation
├── dashboard-service/          # live dashboard + API + shared policy + SQLite volume
├── docker-compose.yml
├── Jenkinsfile                 # main Windows Jenkins pipeline
└── Jenkinsfile.single-fix      # parameterized AI remediation job
```

## Jenkins credentials — already created

Use these exact IDs:

| ID | Type | Purpose |
|---|---|---|
| `github-token` | Secret text | GitHub PAT |
| `dockerhub-creds` | Username + password | Docker Hub username + access token |
| `groq-api-key` | Secret text | Groq AI remediation |

The repository is configured as `KowshikaM/Shift_left_Devsecops` and the Docker Hub namespace as `kowshika8`.

**Never put the actual API keys in this repository or this README.**

## Fresh setup after extracting this ZIP

### 1. Open the extracted folder

```powershell
cd "secure-devops-pipeline"
```

### 2. Configure the dashboard → Jenkins connection

Copy the sample and set your Jenkins account name and a newly generated Jenkins API token in the local, ignored `.env` file:

```powershell
Copy-Item .env.example .env
```

Never commit `.env`. The old API token that was previously present in Compose should be revoked and replaced because removing it from the current file does not remove it from Git history. Do not put the Groq, GitHub, or Docker Hub secrets in `.env`.

Because Jenkins is running directly on Windows and the dashboard runs in Docker, the compose file already uses:

```text
JENKINS_URL=http://host.docker.internal:8080
```

### 3. Start the dashboard

```powershell
docker compose up -d --build
docker compose ps
```

Open:

```text
http://localhost:2001
```

The first screen can correctly say that no builds have been recorded yet.

### 4. Jenkins main job

Create/update the Pipeline job:

- Pipeline from SCM
- Repository: `https://github.com/KowshikaM/Shift_left_Devsecops.git`
- Script Path: `Jenkinsfile`

The Jenkinsfile is already aligned to the repository and Docker Hub namespace.

### 5. Jenkins AI job

Create a second Pipeline job named exactly:

```text
ai-single-fix
```

Use the same SCM repository and set:

```text
Script Path: Jenkinsfile.single-fix
```

The parameters are defined by the Jenkinsfile.

### 6. Jenkins agent requirements

The Windows Jenkins agent must be able to run:

```powershell
docker --version
python --version
git --version
kubectl version --client
node --version
npm --version
```

Docker Desktop must be running.

The Kubernetes context configured in the main Jenkinsfile is:

```text
kind-kind
```

If you are using Minikube instead, change:

```groovy
KUBE_CONTEXT = 'kind-kind'
```

to your real context name.

Check with:

```powershell
kubectl config get-contexts
```

If Jenkins runs as a Windows service under another account, make sure that account can access the Docker CLI and Kubernetes credentials.

### 7. GitHub webhook

Configure GitHub:

**Repository → Settings → Webhooks → Add webhook**

For the Jenkins job, use your Jenkins webhook endpoint. The exact URL depends on how your Jenkins instance is exposed. The important part is that GitHub must be able to reach Jenkins; `localhost` cannot be used by GitHub.

### 8. First run — intentionally FAIL

Do not fix the vulnerable files yet.

Run **Build Now**.

The first build is expected to fail because the demo intentionally contains:

- a fake AWS-style secret for Gitleaks
- an unsafe SQL concatenation pattern for Semgrep
- an old dependency for Trivy
- a root/insecure Dockerfile
- a Kubernetes deployment without the required security context/resources and with a `latest` image

The gate should write:

```text
gate-status.txt = FAIL
```

The push and deployment stages must be skipped.

The results should still be published to:

```text
http://localhost:2001
```

### 9. Verify dashboard history

The dashboard should show:

- failed build
- severity counts
- scanner findings
- open remediation tickets
- build trend
- audit event

A later passing build must not erase the failed build.

The dashboard ingestion is idempotent for the same build number + commit, so repeated publish calls from one Jenkins build update that build instead of creating duplicate history rows.

### 10. AI remediation flow

From an open ticket, click:

**Apply AI fix**

The dashboard triggers `ai-single-fix`.

The API independently enforces LOW/MEDIUM non-secret eligibility; a forged request for HIGH/CRITICAL is rejected. The existing `ai-single-fix` job then:

1. Checks out the finding's repository revision and runs full baseline scans.
2. Confirms the requested finding and severity against fresh scanner output.
3. Sends Groq the scanner metadata, project context, and affected file only.
4. Validates the structured proposal and a unified diff restricted to that one file.
5. Creates an isolated `ai-remediation/` branch and applies the validated diff.
6. Runs the Node application tests, then rebuilds and runs Semgrep, Gitleaks, Trivy, and both OPA/Conftest checks again.
7. Compares before/after results; if tests fail, scans fail, the target remains, or new findings appear, it restores the original file and marks the ticket for manual review.
8. If checks pass, commits only the approved file, pushes the branch, and opens a PR for human review.

This job's PASS means the requested finding was validated and is ready for PR review. It does not authorize deployment. The main pipeline's complete Security Gate remains required for image publishing and Kubernetes deployment.

There is no automatic merge and no AI deployment.

### 11. Passing build

After the vulnerable issues are fixed and the remediation commit is merged/pushed:

```text
GitHub push
  ↓
Jenkins
  ↓
all scanners PASS
  ↓
Security Gate PASS
  ↓
Docker Hub: kowshika8/secure-devops-demo:<BUILD_NUMBER>
  ↓
kind/minikube
```

Verify:

```powershell
kubectl get pods -n devsecops-demo
kubectl get svc -n devsecops-demo
kubectl get deployment -n devsecops-demo
```

### 12. Tests

Run the application smoke tests in a local Node environment after installing its dependencies:

```powershell
npm install --prefix app
npm test --prefix app
```

Run the Python policy, scanner-normalization, patch-control, and dashboard authorization tests:

```powershell
python -m unittest discover -s tests -v
```

The dashboard should retain both the failed and successful build.

## Why the first build is intentionally insecure

This is a controlled demonstration of shift-left security. The application is not the final project; the project is the enforcement system around it.

The intended mentor demonstration is:

**vulnerable commit → Jenkins → real scanner findings → BLOCKED → dashboard evidence → AI/manual remediation → validated PR → human merge → Jenkins → PASS → Docker Hub → Kubernetes**

## Important safety rules

- No API key is committed to Git.
- No secret is printed by the dashboard or AI adapter.
- Gitleaks content is never sent to AI.
- AI cannot merge.
- AI cannot deploy.
- A failed gate cannot push/deploy.
- Missing/invalid scanner evidence blocks.
- `latest` is never pushed or deployed.
- Deployment uses the exact immutable build tag that passed the gate.
- Manual remediation remains available if AI is unavailable.
