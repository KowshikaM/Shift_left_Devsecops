# Local configuration checklist

Already configured in Jenkins Credentials:
- github-token
- dockerhub-creds
- openai-api-key
- groq-api-key

Still required in docker-compose.yml:
- JENKINS_USER
- JENKINS_API_TOKEN

Before first run:
- Dashboard: http://localhost:2001
- Jenkins: http://localhost:8080
- Main job script: Jenkinsfile
- AI job name: ai-single-fix
- Kubernetes context: kind-kind (or change Jenkinsfile if using Minikube)

Never commit real credentials.
