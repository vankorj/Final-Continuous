pipeline {
    agent any

    environment {
        // Docker Hub credentials and image info
        DOCKERHUB_CREDENTIALS = 'docker-id'
        IMAGE_NAME = 'vankorj/finalimage'

        // Trivy config
        TRIVY_SEVERITY = "HIGH,CRITICAL"

        // ZAP config
        TARGET_URL = "http://45.79.140.194/"
        REPORT_HTML = "zap_report.html"
        REPORT_JSON = "zap_report.json"
        ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
        REPORT_DIR = "${env.WORKSPACE}/zap_reports"
    }

    stages {

        stage('Cloning Git') {
            steps { checkout scm }
        }

        stage('SAST-TEST') {
            steps {
                script {
                    def snykInstalled = false
                    try {
                        tool name: 'Snyk-installations', type: 'io.snyk.jenkins.tools.SnykInstallation'
                        snykInstalled = true
                    } catch (err) {
                        echo "Snyk installation not found. Skipping SAST-TEST."
                    }

                    if (snykInstalled) {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            snykSecurity(
                                snykInstallation: 'Snyk-installations',
                                snykTokenId: 'Snyk-API-token',
                                severity: 'critical'
                            )
                        }
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            agent any
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        def scannerHome = tool 'SonarQube-Scanner'
                        withSonarQubeEnv('SonarQube-installations') {
                            sh """
                                ${scannerHome}/bin/sonar-scanner \
                                -Dsonar.projectKey=gameapp \
                                -Dsonar.sources=.
                            """
                        }
                    }
                }
            }
        }

        stage('BUILD-AND-TAG') {
            agent any
            steps {
                script {
                    echo "Building Docker image ${IMAGE_NAME}..."
                    app = docker.build("${IMAGE_NAME}")
                    app.tag("latest")
                }
            }
        }

        stage('POST-TO-DOCKERHUB') {
            agent any
            steps {
                script {
                    echo "Pushing to DockerHub..."
                    docker.withRegistry('https://registry.hub.docker.com', "${DOCKERHUB_CREDENTIALS}") {
                        app.push("latest")
                    }
                }
            }
        }

        stage("SECURITY-IMAGE-SCANNER") {
            steps {
                script {
                    echo "Running Trivy scan..."
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        // JSON report
                        sh """
                            docker run --rm -v \$(pwd):/workspace aquasec/trivy:latest image \
                            --exit-code 0 \
                            --format json \
                            --output /workspace/trivy-report.json \
                            --severity ${TRIVY_SEVERITY} \
                            ${IMAGE_NAME}
                        """
                        // HTML report
                        sh """
                            docker run --rm -v \$(pwd):/workspace aquasec/trivy:latest image \
                            --exit-code 0 \
                            --format template \
                            --template "@/contrib/html.tpl" \
                            --output /workspace/trivy-report.html \
                            ${IMAGE_NAME}
                        """
                    }
                    archiveArtifacts artifacts: "trivy-report.json,trivy-report.html", allowEmptyArchive: true
                }
            }
        }

        stage("Summarize Trivy Findings") {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        if (!fileExists("trivy-report.json")) {
                            echo "No Trivy report."
                            return
                        }

                        def highCount = sh(
                            script: "grep -o '\"Severity\": \"HIGH\"' trivy-report.json | wc -l",
                            returnStdout: true
                        ).trim()

                        def criticalCount = sh(
                            script: "grep -o '\"Severity\": \"CRITICAL\"' trivy-report.json | wc -l",
                            returnStdout: true
                        ).trim()

                        echo "Trivy Findings Summary - HIGH: ${highCount}, CRITICAL: ${criticalCount}"
                    }
                }
            }
        }

        stage('DAST') {
            steps {
                script {
                    echo "Running OWASP ZAP..."
                    sh "mkdir -p ${REPORT_DIR}"
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh """
                            docker run --rm --user root --network host \
                            -v ${REPORT_DIR}:/zap/wrk \
                            -t ${ZAP_IMAGE} zap-baseline.py \
                            -t ${TARGET_URL} \
                            -r ${REPORT_HTML} -J ${REPORT_JSON} || true
                        """
                    }
                    archiveArtifacts artifacts: "zap_reports/*", allowEmptyArchive: true
                }
            }
        }

        stage('DEPLOYMENT') {
            agent any
            steps {
                script {
                    echo "Deploying using docker-compose..."
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        dir("${WORKSPACE}") {
                            sh """
                                docker-compose down || true
                                docker-compose up -d || true
                                docker ps || true
                            """
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            // Publish Trivy report
            publishHTML(target: [
                reportName: 'Trivy Image Security Report',
                reportDir: '.',
                reportFiles: 'trivy-report.html',
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            // Publish ZAP report
            publishHTML(target: [
                reportName: 'OWASP ZAP DAST Report',
                reportDir: 'zap_reports',
                reportFiles: 'zap_report.html',
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            echo 'Pipeline completed (success or fail).'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}