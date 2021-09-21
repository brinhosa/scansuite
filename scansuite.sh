#!/bin/bash

############
### ScanSuite provides the automation of code (SAST) and dependency (OAST) analysis. It also invokes the dynamic websites scans (DAST).
### Leverages GitLab images as well as other known open source tools. Results are exported to DefectDojo.
###
### Author: Sergey Egorov
### Feel free to contribute.
############

dojo_host='http://YOUR_IP:YOUR_PORT'
dojo_apikey='YOUR_KEY'
dojo_csrftoken='YOUR_TOKEN'

init_product () {
  echo "Creating New Product ..."
    curl -X POST "$dojo_host/api/v2/products/" -H "accept: application/json" -H "Content-Type: application/json" -H "X-CSRFToken: $dojo_csrftoken" -H "Authorization: Token $dojo_apikey" -d "{  \"name\": \"$product\",  \"description\": \"$product\",  \"prod_type\": 1}"
}

init_engage () {
  echo "Creating New Engagement ..."
    curl -X POST "$dojo_host/api/v2/engagements/" -H "accept: application/json" -H "Content-Type: multipart/form-data" -H "X-CSRFToken: $dojo_csrftoken" -H "Authorization: Token $dojo_apikey" -F "name=AppEngagement" -F "description=AppEngagement" -F "target_start=2021-05-20" -F "target_end=2022-05-20" -F "deduplication_on_engagement=true" -F "product=$product_id"
}

upload () {
  echo "Uploading Results to DefectDojo ..."
  curl -X POST "$dojo_host/api/v2/import-scan/" -H  "accept: application/json" -H  "Content-Type: multipart/form-data" -H  "X-CSRFToken: $dojo_csrftoken" -H "Authorization: Token $dojo_apikey" -F "minimum_severity=Low" -F "active=true" -F "verified=true" -F "scan_type=$scan_type" -F "file=@$report_path;type=application/json" -F "engagement=$engagement"
}

scan () {
  echo "Starting the scan ..."
  docker run --rm --volume $(pwd):/src --volume /tmp:/report $container /analyzer r --target-dir /src --artifact-dir /report --max-depth 10
  upload
}

scan_secrets () {
  echo "Starting the Secrets scan ..."
  docker run --rm --volume $(pwd):/src --volume /tmp:/report $container /analyzer r --max-depth 10 --full-scan --target-dir /src --artifact-dir /report
  upload
}

engagement=$2
repo='registry.gitlab.com/gitlab-org/security-products/analyzers'

case $1 in

# Create new product and Engagement
  init_product)
    product="$2"
    init_product
    ;;

  init_engage)
    product_id="$2"
    init_engage
    ;;

# Static Analyzers

  java)
    container="$repo/spotbugs:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;
  
  python)
    container="$repo/bandit:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  js_eslint)
    container="$repo/eslint:2"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;
  
  js_semgrep)
    container="$repo/semgrep:2"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  php)
    container="$repo/phpcs-security-audit:2"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  net)
    container="$repo/security-code-scan:2"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  mobsf)
    container="$repo/mobsf:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  nodejs)
    container="$repo/nodejs-scan:2"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  go)
    container="$repo/gosec:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  ruby)
    container="$repo/brakeman:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  cscan)
    container="$repo/flawfinder:latest"
    scan_type='"GitLab SAST Report"'
    report_path='/tmp/gl-sast-report.json'
    scan
    ;;

  secrets)
    echo "DefectDojo doesn't support this scan type. Parse the results manually."
    container="$repo/secrets:3"
    scan_type='GitLab SAST Report'
    report_path='/tmp/gl-secret-detection-report.json'
    scan_secrets
    ;;

# Dynamic analyzers

  arachni)
    ~/arachni-1.5.1-0.5.12/bin/arachni $3 --report-save-path=my-appsec.com.afr --timeout 2:0:0 --browser-cluster-ignore-images --http-ssl-verify-host --scope-exclude-binaries --checks '*,-sql_injection_timing,-timing_attacks,-code_injection_timing,-os_cmd_injection_timing' --output-only-positives
    ~/arachni-1.5.1-0.5.12/bin/arachni_reporter my-appsec.com.afr --reporter=json:outfile=arachni.json
    scan_type='"Arachni Scan"'
    report_path='arachni.json'
    upload
    ;;

  zap)
    # ToDo
    ;;

  nikto)
    docker run --rm -v $(pwd):/tmp hysnsec/nikto -h $3 -o /tmp/nikto-output.xml
    scan_type='"Nikto Scan"'
    report_path='nikto-output.xml'
    upload
    ;;

  sslyze)
    docker run --rm -v $(pwd):/tmp hysnsec/sslyze --regular $3 --json_out /tmp/sslyze-output.json
    scan_type='"Sslyze Scan"'
    report_path='sslyze-output.json'
    upload
    ;;

  nmap)
    docker run --rm -v $(pwd):/tmp hysnsec/nmap $3 -oX /tmp/nmap-output.xml
    scan_type='"Nmap Scan"'
    report_path='nmap-output.xml'
    upload
    ;;

# Dependency checks

  safety)
    docker run -v $(pwd):/src --rm hysnsec/safety check -r /src/requirements.txt --json -o /src/oast-results.json
    scan_type='"Safety Scan"'
    report_path='oast-results.json'
    upload
    ;;

  dep_check)
    ~/dependency-check/bin/dependency-check.sh --project test --format XML --scan .
    scan_type='"Dependency Check Scan"'
    report_path='dependency-check-report.xml'
    upload
    ;;

  gemnasium)
    container="$repo/gemnasium:latest"
    scan_type='GitLab Dependency Scanning Report'
    report_path='/tmp/gl-dependency-scanning-report.json'
    scan
    ;;

  gemnasium-maven)
    container="$repo/gemnasium-maven:2"
    scan_type='GitLab Dependency Scanning Report'
    report_path='/tmp/gl-dependency-scanning-report.json'
    scan
    ;;

  retire)
    container="$repo/retire.js:2"
    scan_type='GitLab Dependency Scanning Report'
    report_path='/tmp/gl-dependency-scanning-report.json'
    scan
    ;;

# Container checks. Provide the image path.

  container)
    docker build -t $3 .
    trivy image -f json -o trivy.json $3
    scan_type='Trivy Scan'
    report_path='trivy.json'
    upload
    ;;

  *)
    echo -n "unknown"
    ;;
esac