pipeline {
    agent any
 
    environment {
        IMAGE_NAME = 'vankorj/finalimage'
        TRIVY_SEVERITY = "HIGH,CRITICAL"
        ZAP_TARGET_URL = "http://172.236.110.30:3000"
    }
 
    stages {
 
        stage("Install Docker CLI") {
            steps {
                script {
                    echo 'Checking Docker CLI installation...'
                    def dockerCheck = sh(script: 'command -v docker || echo "not found"', returnStdout: true).trim()
                    
                    if (dockerCheck == 'not found') {
                        echo 'Docker CLI not found. Installing...'
                        sh '''
                            apt-get update -qq
                            apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release > /dev/null 2>&1
                            
                            # Add Docker GPG key
                            curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg 2>/dev/null || \
                            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg 2>/dev/null
                            
                            # Add Docker repository
                            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1 || \
                            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1
                            
                            apt-get update -qq
                            apt-get install -y -qq docker-ce-cli containerd.io > /dev/null 2>&1
                        '''
                        echo 'Docker CLI installation completed'
                    } else {
                        echo "Docker CLI found at: ${dockerCheck}"
                    }
                }
            }
        }
 
        stage("Check Docker Availability") {
            steps {
                script {
                    echo 'Validating Docker installation...'
                    def dockerCheck = sh(script: 'which docker', returnStatus: true)
                    if (dockerCheck != 0) {
                        error "Docker command not found! Please install Docker or mount /var/run/docker.sock."
                    }
 
                    // Verify Docker daemon connectivity
                    def dockerDaemon = sh(script: 'docker ps > /dev/null 2>&1', returnStatus: true)
                    if (dockerDaemon != 0) {
                        error "Docker daemon not accessible! Ensure Jenkins has permission to access /var/run/docker.sock."
                    }
 
                    sh 'docker --version'
                    echo 'Docker is installed and accessible.'
                }
            }
        }
 
        stage("Pull Target Container Image") {
            steps {
                script {
                    echo "⬇️ Pulling image: ${IMAGE_NAME}"
                    sh "docker pull ${IMAGE_NAME}"
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
 
        stage("Container Vulnerability Scan (Trivy)") {
            steps {
                script {
                    echo "Scanning Docker image ${IMAGE_NAME} for vulnerabilities..."
 
                    // Generate JSON report - output to stdout and redirect
                    sh """
                        docker run --rm aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format json \
                        --severity ${TRIVY_SEVERITY} \
                        ${IMAGE_NAME} > trivy-report.json
                        
                        echo "=== Trivy JSON report created ==="
                        ls -la trivy-report.json
                    """
 
                    // Generate HTML report - output to stdout and redirect
                    sh """
                        docker run --rm aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format template \
                        --template "@/contrib/html.tpl" \
                        --severity ${TRIVY_SEVERITY} \
                        ${IMAGE_NAME} > trivy-report.html
                        
                        echo "=== Trivy HTML report created ==="
                        ls -la trivy-report.html
                    """
                }
            }
            post {
                always {
                    echo "Archiving Trivy reports..."
                    archiveArtifacts artifacts: 'trivy-report.json,trivy-report.html', allowEmptyArchive: true
                }
            }
        }
 
        stage("Summarize Trivy Vulnerabilities") {
            steps {
                script {
                    if (fileExists('trivy-report.json')) {
                        def reportContent = readFile('trivy-report.json')
                        def reportJson = new groovy.json.JsonSlurper().parseText(reportContent)
 
                        def highCount = 0
                        def criticalCount = 0
 
                        reportJson.Results.each { result ->
                            result.Vulnerabilities?.each { vuln ->
                                switch (vuln.Severity) {
                                    case 'HIGH': highCount++; break
                                    case 'CRITICAL': criticalCount++; break
                                }
                            }
                        }
 
                        echo "=== TRIVY VULNERABILITY SUMMARY ==="
                        echo "HIGH vulnerabilities: ${highCount}"
                        echo "CRITICAL vulnerabilities: ${criticalCount}"
 
                        if (criticalCount > 0) {
                            echo "⚠️ WARNING: Critical vulnerabilities detected: ${criticalCount}"
                        }
                    } else {
                        echo "Trivy JSON report not found!"
                    }
                }
            }
        }
        
        stage("DAST Scan with OWASP ZAP") {
            steps {
                script {
                    echo 'Running OWASP ZAP baseline scan...'

                    // Create a Docker named volume for ZAP reports
                    def volumeName = "zap-reports-${BUILD_NUMBER}"
                    sh "docker volume create ${volumeName}"
                    echo "Created Docker volume: ${volumeName}"

                    // Run ZAP with named volume mount
                    def zapExitCode = sh(script: """
                        docker run --rm --user root --network host \
                        -v ${volumeName}:/zap/wrk:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py -t ${ZAP_TARGET_URL} \
                        -r zap_report.html \
                        -J zap_report.json
                    """, returnStatus: true)

                    echo "ZAP scan finished with exit code: ${zapExitCode}"

                    // Start a long-running container with the volume mounted to extract files
                    def helperContainerId = sh(script: """
                        docker run -d -v ${volumeName}:/data alpine sleep 300
                    """, returnStdout: true).trim()

                    echo "Helper container ID: ${helperContainerId}"

                    // List files in volume
                    echo "Files in volume:"
                    sh "docker exec ${helperContainerId} ls -la /data/"

                    // Use docker cp to copy files from helper container to Jenkins workspace
                    echo "Copying ZAP reports from container to workspace..."
                    sh """
                        docker cp ${helperContainerId}:/data/zap_report.html ./zap_report.html && echo "HTML copied successfully" || echo "Failed to copy HTML"
                        docker cp ${helperContainerId}:/data/zap_report.json ./zap_report.json && echo "JSON copied successfully" || echo "Failed to copy JSON"
                    """

                    // Clean up helper container and volume
                    sh "docker rm -f ${helperContainerId}"
                    sh "docker volume rm ${volumeName}"
                    echo "Cleaned up resources"

                    // Verify files in workspace
                    echo "Verifying files in workspace:"
                    sh "ls -la ./zap_report.* 2>/dev/null || echo 'No ZAP report files found in workspace'"

                    // Parse ZAP JSON report safely
                    if (fileExists('zap_report.json')) {
                        try {
                            def zapContent = readFile('zap_report.json')
                            def zapJson = new groovy.json.JsonSlurper().parseText(zapContent)

                            def highCount = 0
                            def mediumCount = 0
                            def lowCount = 0

                            zapJson.site.each { site ->
                                site.alerts.each { alert ->
                                    switch (alert.risk) {
                                        case 'High': highCount++; break
                                        case 'Medium': mediumCount++; break
                                        case 'Low': lowCount++; break
                                    }
                                }
                            }

                            echo "=== OWASP ZAP DAST SUMMARY ==="
                            echo "High severity issues: ${highCount}"
                            echo "Medium severity issues: ${mediumCount}"
                            echo "Low severity issues: ${lowCount}"
                            
                            if (highCount > 0) {
                                echo "⚠️ WARNING: High severity security issues detected: ${highCount}"
                            }
                        } catch (Exception e) {
                            echo "Failed to parse ZAP JSON report: ${e.message}"
                            echo "Continuing build..."
                        }
                    } else {
                        echo "ZAP JSON report not found, continuing build..."
                    }
                }
            }
            post {
                always {
                    echo 'Archiving ZAP scan reports...'
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true
                }
            }
        }
    }
 
    post {
        always {
            echo '=== Security Scan Pipeline Completed ==='
 
            // Publish Trivy HTML report in Jenkins UI
            publishHTML([
                reportDir: '.',
                reportFiles: 'trivy-report.html',
                reportName: 'Trivy Vulnerability Report',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
            
            // Publish ZAP HTML report in Jenkins UI
            publishHTML([
                reportDir: '.',
                reportFiles: 'zap_report.html',
                reportName: 'OWASP ZAP DAST Report',
                keepAll: true,
                alwaysLinkToLastBuild: true,
                allowMissing: true
            ])
        }
    }
}