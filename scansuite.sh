#!/bin/bash

############
### ScanSuite provides the automation of code (SAST), dependency (SCA), infrastructure as code (IACS) and container analysis. It also invokes the dynamic scans (DAST).
### Leverages GitLab images as well as other known open source tools. Results are exported to DefectDojo.
###
### Author: Sergey Egorov
############

dojo_host=HOST_URL
dojo_apikey=DOJO_API_KEY

init_product () {
  echo "Creating New Product ..."
    curl -k -X POST "$dojo_host/api/v2/products/" -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Token $dojo_apikey" -d "{  \"name\": \"$product\",  \"description\": \"$product\",  \"prod_type\": 1}"
}

init_engage () {
  echo "Creating New Engagement ..."
    curl -k -X POST "$dojo_host/api/v2/engagements/" -H "accept: application/json" -H "Content-Type: multipart/form-data" -H "Authorization: Token $dojo_apikey" -F "name=AppEngagement" -F "description=AppEngagement" -F "target_start=2022-02-12" -F "target_end=2023-05-20" -F "deduplication_on_engagement=true" -F "product=$product_id"
}

upload () {
  echo "Uploading Results to DefectDojo ..."
  curl -k -X POST "$dojo_host/api/v2/import-scan/" -H  "accept: application/json" -H  "Content-Type: multipart/form-data"  -H "Authorization: Token $dojo_apikey" -F "minimum_severity=Low" -F "active=true" -F "verified=true" -F "scan_type=$scan_type" -F "file=@$report_path;type=application/json" -F "engagement=$engagement"
  rm $report_path
}

scan () {
  echo "Starting the scan ..."
  docker run --rm --volume $(pwd):/src --volume $(pwd):/report --user $(id -u):$(id -g) $container /analyzer r --target-dir /src --artifact-dir /report --max-depth 10
  upload
}

install_dep_owasp() {
  DIR="~/scan/dependency-check/"
  VERSION="6.5.3"
  if [ ! -d "$DIR" ]; then
    CURDIR=$(pwd)
    echo "Installing scanner in ${DIR}..."
    mkdir ~/scan
    cd ~/scan && wget https://github.com/jeremylong/DependencyCheck/releases/download/v$VERSION/dependency-check-$VERSION-release.zip && unzip dependency-check-$VERSION-release.zip
    rm dependency-check-$VERSION-release.zip
    cd $CURDIR      
  fi
}

install_trivy() {
  VERSION="0.23.0"
  if ! command -v trivy &> /dev/null
  then
      echo "Installing Trivy ..."
      wget https://github.com/aquasecurity/trivy/releases/download/v$VERSION/trivy_"$VERSION"_Linux-64bit.deb && sudo dpkg -i trivy_"$VERSION"_Linux-64bit.deb
      rm trivy_"$VERSION"_Linux-64bit.deb
  fi
}

install_arachni() {
  DIR="~/scan/arachni-1.5.1-0.5.12/"
  if [ ! -d "$DIR" ]; then
    CURDIR=$(pwd)
    echo "Installing scanner in ${DIR}..."
    mkdir ~/scan
    cd ~/scan && wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && tar -xvf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
    rm arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
    cd $CURDIR
  fi
}

engagement=$2
repo='registry.gitlab.com/gitlab-org/security-products/analyzers'

# When executed inside the Docker
if ! command -v curl &> /dev/null
then
    echo "Installing CURL ..."
    apk add curl
fi

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
    report_path='gl-sast-report.json'
    docker run --rm --volume $(pwd):/src --volume $(pwd):/report $container /analyzer r --target-dir /src --artifact-dir /report --max-depth 10
    upload
    ## Implement the gl-sast-report.json cleanup after upload due to it is owned by root.
    ;;
  
  python)
    container="$repo/bandit:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  eslint)
    container="$repo/eslint:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;
  
  semgrep)
    container="returntocorp/semgrep"
    scan_type='"Semgrep JSON Report"'
    report_path='semgrep-sast-report.json'
    docker run --rm -v "${PWD}:/src" --user $(id -u):$(id -g) $container --config p/owasp-top-ten --json -o $report_path
    upload
    ;;

  php)
    container="$repo/phpcs-security-audit:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  net)
    container="$repo/security-code-scan:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  mobsf)
    container="$repo/mobsf:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  nodejs)
    container="$repo/nodejs-scan:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  go)
    container="$repo/gosec:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  ruby)
    container="$repo/brakeman:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  cscan)
    container="$repo/flawfinder:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

  secrets)
    echo "DefectDojo doesn't support this scan type. Parse the results manually."
    container="$repo/secrets:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-secret-detection-report.json'
    docker run --rm --volume $(pwd):/src --volume $(pwd):/report --user $(id -u):$(id -g) $container /analyzer r --max-depth 10 --full-scan --target-dir /src --artifact-dir /report
    cat $report_path
    rm $report_path
    ;;

# Dynamic analyzers

  arachni)
    install_arachni
    ~/scan/arachni-1.5.1-0.5.12/bin/arachni $3 --report-save-path=arachni-report.afr --timeout 2:0:0 --browser-cluster-ignore-images --http-ssl-verify-host --scope-exclude-binaries --checks '*,-sql_injection_timing,-timing_attacks,-code_injection_timing,-os_cmd_injection_timing' --output-only-positives
    ~/scan/arachni-1.5.1-0.5.12/bin/arachni_reporter arachni-report.afr --reporter=json:outfile=arachni.json
    scan_type='"Arachni Scan"'
    report_path='arachni.json'
    upload
    ;;

  zap)
  #ToDo
    #docker run --rm --volume $(pwd):/src --volume /tmp:/report --user $(id -u):$(id -g) registry.gitlab.com/gitlab-org/security-products/analyzers/dast:latest /analyze -t $3

    ;;

  nikto)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/nikto -h $3 -o /tmp/nikto-output.xml
    scan_type='"Nikto Scan"'
    report_path='nikto-output.xml'
    upload
    ;;

  sslyze)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/sslyze --regular $3 --json_out /tmp/sslyze-output.json
    scan_type='"Sslyze Scan"'
    report_path='sslyze-output.json'
    upload
    ;;

  nmap)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/nmap $3 -oX /tmp/nmap-output.xml
    scan_type='"Nmap Scan"'
    report_path='nmap-output.xml'
    upload
    ;;

# Dependency checks

  dep_owasp)
    install_dep_owasp
    ~/scan/dependency-check/bin/dependency-check.sh --project test --format XML --scan .
    scan_type='"Dependency Check Scan"'
    report_path='dependency-check-report.xml'
    upload
    ;;

  gemnasium)
    container="$repo/gemnasium:latest"
    scan_type='GitLab Dependency Scanning Report'
    report_path='gl-dependency-scanning-report.json'
    scan
    ;;
  
  gemnasium-python)
    container="$repo/gemnasium-python:latest"
    scan_type='GitLab Dependency Scanning Report'
    report_path='gl-dependency-scanning-report.json'
    scan
  ;;

  retire)
    container="$repo/retire.js:latest"
    scan_type='GitLab Dependency Scanning Report'
    report_path='gl-dependency-scanning-report.json'
    scan
    ;;

# Trivy dependency checks
  dep_trivy)
    install_trivy
    trivy fs -f json -o trivy.json --security-checks vuln .
    scan_type='Trivy Scan'
    report_path='trivy.json'
    upload
    ;;

# Trivy Docker image checks.

  image_trivy)
    install_trivy
    docker build -t $3 .
    trivy image -f json -o trivy.json $3
    scan_type='Trivy Scan'
    report_path='trivy.json'
    upload
    ;;

# Infrastructure as Code.

  iacs_kics)
    container="$repo/kics:latest"
    scan_type='"GitLab SAST Report"'
    report_path='gl-sast-report.json'
    scan
    ;;

# Trivy checks
  iacs_trivy)
    install_trivy
    echo "DefectDojo doesn't support this scan type. Parse the results manually."
    trivy fs --security-checks config .
    ;;

  *)
    echo -n "unknown"
    ;;
esac