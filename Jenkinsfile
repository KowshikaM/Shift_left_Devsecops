// Secure DevOps Pipeline — Windows Jenkins agent
// Required: github-token, dockerhub-creds.
// Optional AI keys are used only by Jenkinsfile.single-fix.
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
        DEPLOYED            = '0'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {

        stage('Checkout') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Checkout'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                checkout scm

                powershell '''
                    New-Item -ItemType Directory -Force -Path $env:SCAN_DIR | Out-Null
                    Remove-Item "$env:SCAN_DIR\\*" -Force -ErrorAction SilentlyContinue
                '''
            }
        }

        stage('SAST - Semgrep') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Semgrep'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    & docker run --rm `
                      -v "${env:WORKSPACE}:/src" `
                      returntocorp/semgrep `
                      semgrep scan `
                      --config p/owasp-top-ten `
                      --config p/javascript `
                      --json `
                      --output /src/semgrep-results.json `
                      /src/app

                    $code = $LASTEXITCODE

                    Set-Content "$env:SCAN_DIR\\semgrep.status" $code

                    if (!(Test-Path "semgrep-results.json")) {
                        '{}' | Set-Content semgrep-results.json
                    }

                    exit 0
                '''
            }
        }

        stage('Secret Detection - Gitleaks') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Gitleaks'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    & docker run --rm `
                      -v "${env:WORKSPACE}:/repo" `
                      zricethezav/gitleaks:latest `
                      detect `
                      --source /repo `
                      --no-git `
                      --report-format json `
                      --report-path /repo/gitleaks-results.json

                    $code = $LASTEXITCODE

                    Set-Content "$env:SCAN_DIR\\gitleaks.status" $code

                    if (!(Test-Path "gitleaks-results.json")) {
                        '[]' | Set-Content gitleaks-results.json
                    }

                    exit 0
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Docker Image Build'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    & docker build `
                      -t "${env:IMAGE_NAME}:${env:IMAGE_TAG}" .

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }
                '''
            }
        }

        stage('Container Scan - Trivy') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Trivy'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    & docker save `
                      "${env:IMAGE_NAME}:${env:IMAGE_TAG}" `
                      -o "${env:WORKSPACE}\\trivy-image.tar"

                    if ($LASTEXITCODE -ne 0) {
                        Set-Content "$env:SCAN_DIR\\trivy.status" 1
                        exit 0
                    }

                    & docker run --rm `
                      -v "${env:WORKSPACE}:/out" `
                      aquasec/trivy:latest `
                      image `
                      --input /out/trivy-image.tar `
                      --format json `
                      --severity CRITICAL,HIGH,MEDIUM `
                      --timeout 10m `
                      1> trivy-results.json `
                      2> trivy-console.log

                    $code = $LASTEXITCODE

                    Set-Content "$env:SCAN_DIR\\trivy.status" $code

                    if (!(Test-Path "trivy-results.json")) {
                        '{}' | Set-Content trivy-results.json
                    }

                    Remove-Item "trivy-image.tar" -Force -ErrorAction SilentlyContinue

                    exit 0
                '''
            }
        }

        stage('Policy Check - OPA/Conftest') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'OPA / Conftest'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    & docker run --rm `
                      -v "${env:WORKSPACE}:/project" `
                      openpolicyagent/conftest `
                      test `
                      /project/Dockerfile `
                      --policy /project/policy `
                      --output json |
                      Set-Content dockerfile-policy-results.json

                    $dockerCode = $LASTEXITCODE

                    Set-Content "$env:SCAN_DIR\\docker-policy.status" $dockerCode


                    & docker run --rm `
                      -v "${env:WORKSPACE}:/project" `
                      openpolicyagent/conftest `
                      test `
                      /project/k8s/deployment.yaml `
                      --policy /project/policy `
                      --output json |
                      Set-Content k8s-policy-results.json

                    $k8sCode = $LASTEXITCODE

                    Set-Content "$env:SCAN_DIR\\k8s-policy.status" $k8sCode


                    if (!(Test-Path "dockerfile-policy-results.json")) {
                        '[]' | Set-Content dockerfile-policy-results.json
                    }

                    if (!(Test-Path "k8s-policy-results.json")) {
                        '[]' | Set-Content k8s-policy-results.json
                    }

                    exit 0
                '''
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Security Gate'
                    env.PIPELINE_STATUS = 'RUNNING'

                    def status = powershell(
                        returnStatus: true,
                        script: 'python scripts/evaluate_gate.py'
                    )

                    if (status == 0) {
                        powershell '''
                            Set-Content -Path "gate-status.txt" -Value "PASS"
                        '''

                        env.GATE_STATUS = 'PASS'
                        echo 'Security Gate: PASS'
                    } else {
                        powershell '''
                            Set-Content -Path "gate-status.txt" -Value "FAIL"
                    '''

                        env.GATE_STATUS = 'FAIL'
                        echo 'Security Gate: FAIL'
                    }

                    echo "Security Gate file: ${readFile('gate-status.txt').trim()}"
                }
            }
        }

        stage('Generate Dashboard Report') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Generating Dashboard Report'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    $env:REPO_URL = "${env:REPO_URL}"
                    $env:JENKINS_BUILD_URL = "${env:BUILD_URL}"

                    if (!$env:GIT_BRANCH) {
                        $env:GIT_BRANCH = "main"
                    }

                    if (!$env:GIT_COMMIT) {
                        $env:GIT_COMMIT = "local"
                    }

                    python scripts/generate_dashboard.py
                '''

                archiveArtifacts artifacts: 'dashboard/report.html, *-results.json, .scan-status/*.status',
                    allowEmptyArchive: true
            }
        }

        stage('Publish to Live Dashboard') {
            steps {
                script {
                    env.PIPELINE_STAGE = 'Publishing Dashboard'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    python scripts/publish_to_dashboard.py
                '''
            }
        }

        stage('Create Remediation Tickets') {
            when {
                expression {
                    return fileExists('gate-status.txt') &&
                            readFile('gate-status.txt').trim().toUpperCase() == 'FAIL'
                }
            }

            steps {
                script {
                    env.PIPELINE_STAGE = 'Creating Remediation Tickets'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    python scripts/create_remediation_tickets.py
                '''
            }
        }

        stage('Push Immutable Image') {
            when {
                expression {
                    return fileExists('gate-status.txt') &&
                            readFile('gate-status.txt').trim().toUpperCase() == 'PASS'
                }
            }

            steps {
                script {
                    env.PIPELINE_STAGE = 'Pushing Immutable Docker Image'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub-creds',
                        usernameVariable: 'DOCKER_USER',
                        passwordVariable: 'DOCKER_PASS'
                    )
                ]) {
                    powershell '''
                        $env:DOCKER_PASS | docker login `
                          -u $env:DOCKER_USER `
                          --password-stdin

                        if ($LASTEXITCODE -ne 0) {
                            exit $LASTEXITCODE
                        }

                        $registryImage = "$env:DOCKERHUB_NAMESPACE/$env:IMAGE_NAME:$env:IMAGE_TAG"

                        docker tag `
                          "$env:IMAGE_NAME:$env:IMAGE_TAG" `
                          "$registryImage"

                        if ($LASTEXITCODE -ne 0) {
                            exit $LASTEXITCODE
                        }

                        docker push "$registryImage"

                        if ($LASTEXITCODE -ne 0) {
                            exit $LASTEXITCODE
                        }

                        docker logout
                    '''
                }
            }
        }

        stage('Deploy to kind/minikube') {
            when {
                expression {
                    return fileExists('gate-status.txt') &&
                            readFile('gate-status.txt').trim().toUpperCase() == 'PASS'
                }
            }

            steps {
                script {
                    env.PIPELINE_STAGE = 'Kubernetes Deployment'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    kubectl config use-context $env:KUBE_CONTEXT

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }

                    kubectl apply -f k8s/service.yaml

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }

                    kubectl apply -f k8s/deployment.yaml

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }

                    $registryImage = "$env:DOCKERHUB_NAMESPACE/$env:IMAGE_NAME:$env:IMAGE_TAG"

                    kubectl -n devsecops-demo set image deployment/demo-app `
                      "demo-app=$registryImage"

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }

                    kubectl -n devsecops-demo rollout status `
                      deployment/demo-app `
                      --timeout=120s

                    if ($LASTEXITCODE -ne 0) {
                        exit $LASTEXITCODE
                    }
                '''

                script {
                    env.DEPLOYED = '1'
                }
            }
        }

        stage('Record Deployment') {
            when {
                expression {
                    return fileExists('gate-status.txt') &&
                            readFile('gate-status.txt').trim().toUpperCase() == 'PASS' &&
                            env.DEPLOYED == '1'
                }
            }

            steps {
                script {
                    env.PIPELINE_STAGE = 'Deployment Complete'
                    env.PIPELINE_STATUS = 'RUNNING'
                }

                powershell '''
                    python scripts/publish_to_dashboard.py
                '''
            }
        }

        stage('Finalize Pipeline') {
            steps {
                script {
                    def finalGate = fileExists('gate-status.txt')
                        ? readFile('gate-status.txt').trim().toUpperCase()
                        : 'FAIL'
                    env.GATE_STATUS = finalGate
                    if (finalGate == 'PASS') {
                        env.PIPELINE_STAGE = 'Pipeline Completed Successfully'
                        env.PIPELINE_STATUS = 'PASSED'


                        echo 'Pipeline completed successfully.'

                        powershell '''
                           $env:PUBLISH_FINDINGS = "1"
                           python scripts/publish_to_dashboard.py
                        '''
                        currentBuild.result = 'SUCCESS'
                    } else {
                        env.PIPELINE_STAGE = 'Pipeline Blocked by Security Gate'
                        env.PIPELINE_STATUS = 'FAILED'


                        echo 'Pipeline blocked by Security Gate.'

                        powershell '''
                           $env:PUBLISH_FINDINGS = "1"
                           python scripts/publish_to_dashboard.py
                        '''

                        currentBuild.result = 'FAILURE'
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Gate status: ${env.GATE_STATUS}"
            echo "Build result: ${currentBuild.result ?: 'UNKNOWN'}"
        }

        failure {
            echo 'Pipeline blocked or failed. Review the dashboard and Jenkins archived report.'
        }
    }
}
