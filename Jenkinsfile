pipeline {
    agent any

    environment {
        // Docker Hub credentials and image info
        DOCKERHUB_CREDENTIALS = 'docker-id'
        IMAGE_NAME = 'vankorj/finalimage'

        // Trivy config
        TRIVY_SEVERITY = "HIGH,CRITICAL"

        // ZAP config
        TARGET_URL = "http://172.236.110.30:3000"
        REPORT_HTML = "zap_report.html"
        REPORT_JSON = "zap_report.json"
        ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
        REPORT_DIR = "${env.WORKSPACE}/zap_reports"
    }

    stages {

        stage('Checkout SCM') {
            steps {
                checkout scm
            }
        }

        stage('Prepare Environment') {
            steps {
                script {
                    // Install Node.js if missing
                    if (!fileExists('/usr/bin/node')) {
                        sh '''
                        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
                        apt-get install -y nodejs
                        '''
                    }
                    
                    // Install docker-compose if missing
                    if (!fileExists('/usr/local/bin/docker-compose')) {
                        sh '''
                        curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                        chmod +x /usr/local/bin/docker-compose
                        '''
                    }
                    
                    // Print versions
                    sh 'node -v && npm -v && docker-compose -v'
                }
            }
        }

        stage('SAST - Snyk') {
            steps {
                snykSecurity(
                    snykInstallation: 'Snyk-installation', // the tool name in Jenkins
                    snykTokenId: 'synk_id',                  // your Snyk credential
                    severity: 'critical'
                )
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
                            --output "/workspace/trivy-report.html" \
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
                        //if (!fileExists("trivy-report.json")) {
                        //    echo "No Trivy report."
                        //    return
                        //}

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

        stage('Deploy') {
            steps {
                script {
                    sh 'docker-compose down || true'
                    sh 'docker-compose up -d || true'
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
                    sh 'ls -R zap_reports'
                    echo "${env.WORKSPACE}"
                    sh 'pwd'
                    archiveArtifacts artifacts: "${env.WORKSPACE}/zap_reports/*", allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline finished."
        }
        failure {
            echo "Pipeline failed!"
        }
    }
}
