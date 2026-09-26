# Local configuration checklist

Already configured in Jenkins Credentials:
- github-token
- dockerhub-creds
- groq-api-key (the only AI provider credential)

Create a local `.env` from `.env.example` and set:
- JENKINS_USER
- JENKINS_API_TOKEN (use a newly generated token; revoke the old token that was previously in Compose)

Optional Jenkins job parameter:
- GROQ_MODEL (defaults to `openai/gpt-oss-20b`)

Before first run:
- Dashboard: http://localhost:2001
- Jenkins: http://localhost:8080
- Main job script: Jenkinsfile
- AI job name: ai-single-fix
- Kubernetes context: kind-kind (or change Jenkinsfile if using Minikube)

Never commit real credentials.
