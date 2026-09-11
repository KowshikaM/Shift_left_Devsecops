# Secure DevOps Pipeline — Shift-Left Security

A local, demo-ready DevSecOps control center that turns a GitHub push into an enforced security decision:

**GitHub → Jenkins → Semgrep/Gitleaks → Docker build → Trivy → OPA/Conftest → Security Gate → Dashboard → Docker Hub → kind/minikube**

A failed build is retained in dashboard history. A passing build is the only build allowed to push and deploy. AI remediation is human-triggered, validated by Jenkins, and opened as a PR; it never merges or deploys.

## Current implementation

- Jenkins Pipeline designed for a **Windows Jenkins agent**.
- Dashboard service runs in Docker at **http://localhost:2001**.
- Persistent dashboard history uses the existing SQLite volume from the supplied project scaffold. This keeps the one-day local demo reliable; MongoDB/RBAC are intentionally not introduced into this revision because they would replace the working dashboard rather than make the core demo safer.
- Real containerized scanners: Semgrep, Gitleaks, Trivy and OPA/Conftest.
- Central gate blocks on CRITICAL/HIGH findings and on missing/invalid scanner evidence or scanner execution errors.
- Docker Hub receives only an immutable build-number tag; `latest` is not pushed or deployed.
- Kubernetes deployment uses the exact registry image tag produced by the passing build.
- AI provider adapter: **OpenAI primary, Groq fallback**. Groq uses its OpenAI-compatible endpoint. Both credentials stay in Jenkins.
- AI never handles Gitleaks secret content. AI changes are restricted to `app/`, `k8s/`, and `Dockerfile`.
- AI fixes are validated by the same gate before a branch is pushed and a GitHub PR is created.
- Human review/merge remains mandatory.
- Manual remediation remains available when AI is unavailable.

OpenAI documents API keys as environment-managed credentials; Groq documents the OpenAI-compatible base URL `https://api.groq.com/openai/v1`. See the project notes below for the exact Jenkins credential IDs.

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
│   ├── ai_fix_single.py        # OpenAI/Groq remediation adapter
│   └── create_ai_pr.py         # creates PR only after validation
├── dashboard-service/          # live dashboard + API + SQLite volume
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
| `openai-api-key` | Secret text | OpenAI AI remediation |
| `groq-api-key` | Secret text | Groq fallback remediation |

The repository is configured as `KowshikaM/Shift_left_Devsecops` and the Docker Hub namespace as `kowshika8`.

**Never put the actual API keys in this repository or this README.**

## Fresh setup after extracting this ZIP

### 1. Open the extracted folder

```powershell
cd "secure-devops-pipeline"
```

### 2. Configure the dashboard → Jenkins connection

Open `docker-compose.yml` and replace only:

```yaml
JENKINS_USER: "REPLACE_WITH_YOUR_JENKINS_USERNAME"
JENKINS_API_TOKEN: "REPLACE_WITH_YOUR_JENKINS_API_TOKEN"
```

Do not put OpenAI, Groq, GitHub or Docker Hub secrets in this file.

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

The job:

1. Checks out the vulnerable commit.
2. Calls OpenAI first.
3. Falls back to Groq if OpenAI is unavailable.
4. Never sends Gitleaks secret findings to an AI provider.
5. Restricts AI changes to the allowed project files.
6. Runs Semgrep, Gitleaks, Trivy and OPA/Conftest again.
7. Runs the centralized Security Gate.
8. Stops if the fix still fails.
9. Only after a PASS does it create a new branch and push it.
10. Creates a GitHub PR.
11. Calls the dashboard back with the explanation and PR URL.
12. Human reviews and merges the PR.

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
