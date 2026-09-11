// Secure DevOps Pipeline — Windows Jenkins agent
// Required: github-token, dockerhub-creds. Optional AI keys are used only by Jenkinsfile.single-fix.
// Dashboard: http://localhost:2001 | Jenkins: http://localhost:8080

pipeline {
    agent any

    environment {
        REPO_URL            = 'https://github.com/KowshikaM/Shift_left_Devsecops.git'
        DOCKERHUB_NAMESPACE = 'kowshika8'
        KUBE_CONTEXT        = 'kind-kind'
        IMAGE_NAME          = 'secure-devops-demo'
        IMAGE_TAG           = "${env.BUILD_NUMBER}"
        GITHUB_REPOSITORY   = 'KowshikaM/Shift_left_Devsecops'
        GITHUB_TOKEN        = credentials('github-token')
        DASHBOARD_URL       = 'http://localhost:2001'
        SCAN_DIR            = '.scan-status'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                powershell '''
                    New-Item -ItemType Directory -Force -Path $env:SCAN_DIR | Out-Null
                    Remove-Item "$env:SCAN_DIR\\*" -Force -ErrorAction SilentlyContinue
                '''
            }
        }

        stage('SAST - Semgrep') {
            steps {
                powershell '''
                    & docker run --rm -v "${env:WORKSPACE}:/src" returntocorp/semgrep semgrep scan `
                      --config p/owasp-top-ten --config p/javascript `
                      --json --output /src/semgrep-results.json /src/app
                    $code = $LASTEXITCODE
                    Set-Content "$env:SCAN_DIR\\semgrep.status" $code
                    if (!(Test-Path "semgrep-results.json")) { '{}' | Set-Content semgrep-results.json }
                    exit 0
                '''
            }
        }

        stage('Secret Detection - Gitleaks') {
            steps {
                powershell '''
                    & docker run --rm -v "${env:WORKSPACE}:/repo" zricethezav/gitleaks:latest detect `
                      --source /repo --no-git --report-format json --report-path /repo/gitleaks-results.json
                    $code = $LASTEXITCODE
                    Set-Content "$env:SCAN_DIR\\gitleaks.status" $code
                    if (!(Test-Path "gitleaks-results.json")) { '[]' | Set-Content gitleaks-results.json }
                    exit 0
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                powershell '''
                    & docker build -t "${env:IMAGE_NAME}:${env:IMAGE_TAG}" .
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                '''
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                powershell '''
                    & docker save "${env:IMAGE_NAME}:${env:IMAGE_TAG}" -o "${env:WORKSPACE}\\trivy-image.tar"
                    if ($LASTEXITCODE -ne 0) {
                        Set-Content "$env:SCAN_DIR\\trivy.status" 1
                        exit 0
                    }
                    & docker run --rm -v "${env:WORKSPACE}:/out" aquasec/trivy:latest image `
                      --input /out/trivy-image.tar --format json --output /out/trivy-results.json `
                      --severity CRITICAL,HIGH,MEDIUM
                    $code = $LASTEXITCODE
                    Set-Content "$env:SCAN_DIR\\trivy.status" $code
                    if (!(Test-Path "trivy-results.json")) { '{}' | Set-Content trivy-results.json }
                    Remove-Item "trivy-image.tar" -Force -ErrorAction SilentlyContinue
                    exit 0
                '''
            }
        }

        stage('Policy Check - OPA/Conftest') {
            steps {
                powershell '''
                    & docker run --rm -v "${env:WORKSPACE}:/project" openpolicyagent/conftest test `
                      /project/Dockerfile --policy /project/policy --output json | Set-Content dockerfile-policy-results.json
                    $dockerCode = $LASTEXITCODE
                    Set-Content "$env:SCAN_DIR\\docker-policy.status" $dockerCode

                    & docker run --rm -v "${env:WORKSPACE}:/project" openpolicyagent/conftest test `
                      /project/k8s/deployment.yaml --policy /project/policy --output json | Set-Content k8s-policy-results.json
                    $k8sCode = $LASTEXITCODE
                    Set-Content "$env:SCAN_DIR\\k8s-policy.status" $k8sCode

                    if (!(Test-Path "dockerfile-policy-results.json")) { '[]' | Set-Content dockerfile-policy-results.json }
                    if (!(Test-Path "k8s-policy-results.json")) { '[]' | Set-Content k8s-policy-results.json }
                    exit 0
                '''
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    def status = powershell(returnStatus: true, script: 'python scripts/evaluate_gate.py')
                    currentBuild.result = (status == 0) ? 'SUCCESS' : 'FAILURE'
                    echo "Security gate result: ${currentBuild.result}"
                }
            }
        }

        stage('Generate Dashboard Report') {
            steps {
                powershell '''
                    $env:REPO_URL = "${env:REPO_URL}"
                    $env:JENKINS_BUILD_URL = "${env:BUILD_URL}"
                    if (!$env:GIT_BRANCH) { $env:GIT_BRANCH = "main" }
                    if (!$env:GIT_COMMIT) { $env:GIT_COMMIT = "local" }
                    python scripts/generate_dashboard.py
                '''
                publishHTML(target: [
                    reportName: 'Security Dashboard',
                    reportDir: 'dashboard',
                    reportFiles: 'report.html',
                    keepAll: true,
                    alwaysLinkToLastBuild: true,
                    allowMissing: false
                ])
                archiveArtifacts artifacts: 'dashboard/report.html, *-results.json, .scan-status/*.status', allowEmptyArchive: true
            }
        }

        stage('Publish to Live Dashboard') {
            steps {
                powershell 'python scripts/publish_to_dashboard.py'
            }
        }

        stage('Create Remediation Tickets') {
            when { expression { currentBuild.result == 'FAILURE' } }
            steps {
                powershell 'python scripts/create_remediation_tickets.py'
            }
        }

        stage('Push Immutable Image') {
            when { expression { currentBuild.result == 'SUCCESS' } }
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    powershell '''
                        $env:DOCKER_PASS | docker login -u $env:DOCKER_USER --password-stdin
                        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                        $registryImage = "$env:DOCKERHUB_NAMESPACE/$env:IMAGE_NAME:$env:IMAGE_TAG"
                        docker tag "$env:IMAGE_NAME:$env:IMAGE_TAG" "$registryImage"
                        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                        docker push "$registryImage"
                        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                        docker logout
                    '''
                }
            }
        }

        stage('Deploy to kind/minikube') {
            when { expression { currentBuild.result == 'SUCCESS' } }
            steps {
                powershell '''
                    kubectl config use-context $env:KUBE_CONTEXT
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                    kubectl apply -f k8s/service.yaml
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                    kubectl apply -f k8s/deployment.yaml
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                    $registryImage = "$env:DOCKERHUB_NAMESPACE/$env:IMAGE_NAME:$env:IMAGE_TAG"
                    kubectl -n devsecops-demo set image deployment/demo-app "demo-app=$registryImage"
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                    kubectl -n devsecops-demo rollout status deployment/demo-app --timeout=120s
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                '''
                script {
                    env.DEPLOYED = '1'
                }
            }
        }

        stage('Record Deployment') {
            when { expression { currentBuild.result == 'SUCCESS' && env.DEPLOYED == '1' } }
            steps {
                powershell 'python scripts/publish_to_dashboard.py'
            }
        }
    }

    post {
        always { echo "Build result: ${currentBuild.result ?: 'UNKNOWN'}" }
        failure { echo 'Pipeline blocked or failed. Review the dashboard and Jenkins archived report.' }
    }
}
