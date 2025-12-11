pipeline {
    agent any

    environment {
        DOCKERHUB_CREDENTIALS = credentials('docker-id') // your DockerHub credential ID
        TARGET_URL = "http://localhost:3000" // Set default URL for DAST
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

        stage('Build Docker Image') {
            steps {
                script {
                    sh 'docker build -t vankorj/finalimage .'
                    sh 'docker tag vankorj/finalimage vankorj/finalimage:latest'
                }
            }
        }

        stage('Push to DockerHub') {
            steps {
                script {
                    docker.withRegistry('https://registry.hub.docker.com', 'dockerhub-creds') {
                        sh 'docker push vankorj/finalimage:latest'
                    }
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                script {
                    // JSON report
                    sh '''
                    docker run --rm -v $WORKSPACE:/workspace aquasec/trivy:latest image \
                    --exit-code 0 --format json --output /workspace/trivy-report.json \
                    --severity HIGH,CRITICAL vankorj/finalimage
                    '''

                    // HTML report
                    sh '''
                    docker run --rm -v $WORKSPACE:/workspace aquasec/trivy:latest image \
                    --exit-code 0 --format template --template @/contrib/html.tpl \
                    --output /workspace/trivy-report.html vankorj/finalimage
                    '''
                }
            }
        }

        stage('Archive Trivy Reports') {
            steps {
                archiveArtifacts artifacts: 'trivy-report.json,trivy-report.html', allowEmptyArchive: true
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

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    if (env.TARGET_URL) {
                        echo "Running DAST against ${env.TARGET_URL}"
                        // Insert ZAP scanning command here, e.g.:
                        // sh "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' ${TARGET_URL}"
                    } else {
                        echo "TARGET_URL not set, skipping DAST"
                    }
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
