pipeline {
    agent any

    environment {
        DOCKERHUB_CREDENTIALS = 'docker-id'
        IMAGE_NAME = 'vankorj/finalimage'

        TRIVY_SEVERITY = "HIGH,CRITICAL"

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
                    echo "Running Snyk SAST/SCA..."

                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        snykSecurity(
                            snykInstallation: 'Snyk-installation',
                            snykTokenId: 'Snyk-API-token',
                            severity: 'critical'
                        )
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        def scannerHome = tool 'SonarQube-Scanner'
                        withSonarQubeEnv('SonarQube-installations') {
                            sh """
                                ${scannerHome}/bin/sonar-scanner \
                                -Dsonar.projectKey=final \
                                -Dsonar.sources=. 
                            """
                        }
                    }
                }
            }
        }

        stage('BUILD-AND-TAG') {
            steps {
                script {
                    echo "Building Docker image ${IMAGE_NAME}..."
                    def app = docker.build("${IMAGE_NAME}")
                    app.tag("latest")
                    env.IMAGE_ID = "${IMAGE_NAME}:latest"
                }
            }
        }

        stage('POST-TO-DOCKERHUB') {
            steps {
                script {
                    echo "Pushing to DockerHub..."
                    docker.withRegistry('https://registry.hub.docker.com', "${DOCKERHUB_CREDENTIALS}") {
                        docker.image("${IMAGE_NAME}:latest").push()
                    }
                }
            }
        }

        stage("SECURITY-IMAGE-SCANNER") {
            steps {
                script {
                    echo "Running Trivy vulnerability scan..."

                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                        sh """
                            docker run --rm -v \$(pwd):/workspace aquasec/trivy:latest image \
                            --exit-code 0 \
                            --format json \
                            --output /workspace/trivy-report.json \
                            --severity ${TRIVY_SEVERITY} \
                            ${IMAGE_NAME}
                        """

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
                            echo "No Trivy report found."
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

                        echo "Trivy Summary → HIGH: ${highCount}, CRITICAL: ${criticalCount}"
                    }
                }
            }
        }

        stage('DAST') {
            steps {
                script {
                    echo "Running OWASP ZAP DAST scan..."

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
            steps {
                script {
                    echo "Deploying with docker-compose..."

                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
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

    post {
        always {

            publishHTML(target: [
                reportName: 'Trivy Image Security Report',
                reportDir: '.',
                reportFiles: 'trivy-report.html',
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            publishHTML(target: [
                reportName: 'OWASP ZAP DAST Report',
                reportDir: 'zap_reports',
                reportFiles: 'zap_report.html',
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])

            echo 'Pipeline completed.'
        }

        failure {
            echo 'Pipeline failed!'
        }
    }
}
