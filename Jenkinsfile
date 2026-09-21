// Shift-Left Secure DevOps Pipeline — Windows Jenkins agent
// Security controls: Semgrep, Gitleaks, Trivy, OPA/Conftest + centralized gate.
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
        GATE_STATUS         = 'PENDING'
        PIPELINE_STATUS     = 'RUNNING'
        PIPELINE_STAGE      = 'Queued'
        DEPLOYED            = '0'
        PUBLISH_FINDINGS    = '0'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.PIPELINE_STAGE = 'Checkout'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
                powershell '''
                    New-Item -ItemType Directory -Force -Path $env:SCAN_DIR | Out-Null
                    Remove-Item "$env:SCAN_DIR\\*" -Force -ErrorAction SilentlyContinue
                '''
            }
        }

        stage('SAST - Semgrep') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'SAST - Semgrep'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
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
                script {
                    env.PIPELINE_STAGE = 'Secret Detection - Gitleaks'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
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
                script {
                    env.PIPELINE_STAGE = 'Build Docker Image'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
                powershell '''
                    & docker build -t "${env:IMAGE_NAME}:${env:IMAGE_TAG}" .
                    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
                '''
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Container Scan - Trivy'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
                powershell '''
                    & docker save "${env:IMAGE_NAME}:${env:IMAGE_TAG}" -o "${env:WORKSPACE}\\trivy-image.tar"
                    if ($LASTEXITCODE -ne 0) {
                        Set-Content "$env:SCAN_DIR\\trivy.status" 2
                        exit 0
                    }
                    & docker run --rm -v "${env:WORKSPACE}:/out" aquasec/trivy:latest image `
                      --input /out/trivy-image.tar --format json --output /out/trivy-results.json `
                      --severity CRITICAL,HIGH,MEDIUM --timeout 10m
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
                script {
                    env.PIPELINE_STAGE = 'Policy Check - OPA/Conftest'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
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
                    env.PIPELINE_STAGE = 'Security Gate'
                    def status = powershell(returnStatus: true, script: 'python scripts/evaluate_gate.py')
                    if (status == 0) {
                        env.GATE_STATUS = 'PASS'
                        echo 'Security Gate: PASS'
                    } else {
                        env.GATE_STATUS = 'FAIL'
                        echo 'Security Gate: FAIL'
                    }
                    env.PUBLISH_FINDINGS = '1'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
            }
        }

        stage('Generate Dashboard Report') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Generate Dashboard Report'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
                powershell '''
                    $env:REPO_URL = "${env:REPO_URL}"
                    $env:JENKINS_BUILD_URL = "${env:BUILD_URL}"
                    if (!$env:GIT_BRANCH) { $env:GIT_BRANCH = "main" }
                    if (!$env:GIT_COMMIT) { $env:GIT_COMMIT = "local" }
                    python scripts/generate_dashboard.py
                '''
                archiveArtifacts artifacts: 'dashboard/report.html, *-results.json, .scan-status/*.status', allowEmptyArchive: true
            }
        }

        stage('Create Remediation Tickets') {
            when { expression { env.GATE_STATUS == 'FAIL' } }
            steps {
                script {
                    env.PIPELINE_STAGE = 'Create Remediation Tickets'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
                powershell 'python scripts/create_remediation_tickets.py'
            }
        }

        stage('Push Immutable Image') {
            when { expression { env.GATE_STATUS == 'PASS' } }
            steps {
                script {
                    env.PIPELINE_STAGE = 'Push Immutable Image'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
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
            when { expression { env.GATE_STATUS == 'PASS' } }
            steps {
                script {
                    env.PIPELINE_STAGE = 'Deploy to kind/minikube'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
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
                    env.PIPELINE_STAGE = 'Deployment Complete'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
            }
        }

        stage('Finalize Pipeline') {
            steps {
                script {
                    if (env.GATE_STATUS == 'PASS') {
                        env.PIPELINE_STAGE = 'Pipeline Completed Successfully'
                        env.PIPELINE_STATUS = 'PASSED'
                        currentBuild.result = 'SUCCESS'
                    } else {
                        env.PIPELINE_STAGE = 'Pipeline Blocked by Security Gate'
                        env.PIPELINE_STATUS = 'FAILED'
                        currentBuild.result = 'FAILURE'
                    }
                    env.PUBLISH_FINDINGS = '1'
                    powershell 'python scripts/publish_to_dashboard.py'
                }
            }
        }
    }

    post {
        always {
            script {
                if (env.PIPELINE_STATUS == 'RUNNING') {
                    env.PIPELINE_STATUS = 'FAILED'
                    env.PIPELINE_STAGE = 'Pipeline Failed'
                }
                env.PUBLISH_FINDINGS = '1'
                powershell 'python scripts/publish_to_dashboard.py'
                echo "Build result: ${currentBuild.result ?: 'UNKNOWN'}"
            }
        }
        failure {
            echo 'Pipeline blocked or failed. Review the dashboard and Jenkins archived report.'
        }
    }
}
