# Local configuration checklist

Already configured in Jenkins Credentials:
- github-token
- dockerhub-creds
- groq-api-key (the only AI provider credential)

Create this Jenkins Secret text credential:
- ID: dashboard-callback-token (use the same secret as the dashboard callback setting below)

Create a local `.env` from `.env.example` and set:
- JENKINS_USER
- JENKINS_API_TOKEN (use a newly generated token; revoke the old token that was previously in Compose)
- DASHBOARD_CALLBACK_TOKEN (generate a long random secret; store the same value in Jenkins credential `dashboard-callback-token`)

The callback destination is not a build parameter. `Jenkinsfile.single-fix` sets the trusted environment value to `http://localhost:2001`, and `scripts/dashboard_callback.py` rejects other destinations before sending the callback token. If the Jenkins host/dashboard address changes, update both the Pipeline environment value and the allowlist constant in that script after reviewing the destination.

Optional Jenkins job parameter:
- GROQ_MODEL (defaults to `openai/gpt-oss-20b`)

Before first run:
- Dashboard: http://localhost:2001
- Jenkins: http://localhost:8080
- Main job script: Jenkinsfile
- AI job name: ai-single-fix
- Kubernetes context: kind-kind (or change Jenkinsfile if using Minikube)

Never commit real credentials.
