#!/bin/bash

############
### ScanSuite provides the automation of code (SAST), dependency (SCA), infrastructure as code (IACS) and container analysis. It also invokes the dynamic scans (DAST).
### Leverages GitLab images as well as other known open source tools. Results are exported to DefectDojo.
############

dojo_host=HOST_URL
dojo_apikey=DOJO_API_KEY

date=$(date +"%Y-%m-%d")
future_date=$(date -d "+2 years" +"%Y-%m-%d")

init_product () {
  echo "Creating New Product ..."
    prodid=$(curl -k -s -X POST "$dojo_host/api/v2/products/" -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Token $dojo_apikey" -d "{  \"name\": \"$product\",  \"description\": \"$product\",  \"prod_type\": 1}" | cut -d ":" -f2 | cut -d "," -f1)
  echo "Creating New Engagement ..."
    engid=$(curl -k -s -X POST "$dojo_host/api/v2/engagements/" -H "accept: application/json" -H "Content-Type: multipart/form-data" -H "Authorization: Token $dojo_apikey" -F "name=AppEngagement" -F "description=AppEngagement" -F "target_start=$date" -F "target_end=$future_date" -F "deduplication_on_engagement=true" -F "product=$prodid" | cut -d ":" -f2 | cut -d "," -f1)
  echo "Engagement ID: ${engid}"
}

init_engage () {
  echo "Creating New Engagement ..."
    curl -k -X POST "$dojo_host/api/v2/engagements/" -H "accept: application/json" -H "Content-Type: multipart/form-data" -H "Authorization: Token $dojo_apikey" -F "name=AppEngagement" -F "description=AppEngagement" -F "target_start=$date" -F "target_end=$future_date" -F "deduplication_on_engagement=true" -F "product=$product_id"
}

upload () {
  echo "Uploading Results to DefectDojo ..."
  curl -k -X POST "$dojo_host/api/v2/import-scan/" -H  "accept: application/json" -H  "Content-Type: multipart/form-data"  -H "Authorization: Token $dojo_apikey" -F "minimum_severity=Low" -F "active=true" -F "verified=true" -F "scan_type=$scan_type" -F "file=@$report_path;type=application/json" -F "engagement=$engagement"
  rm -f $report_path
}

scan () {
  echo "Starting the scan ..."
  docker run --rm --volume $(pwd):/src --volume $(pwd):/report --user $(id -u):$(id -g) $container /analyzer r --target-dir /src --artifact-dir /report --max-depth 10
  upload
}

install_dep_owasp() {
  DIR=~/apps/dependency-check/

  if ! command -v java &> /dev/null; then
      echo "Installing Java ..."
      sudo apt install -y openjdk-11-jre-headless
  fi

  if [ ! -d "$DIR" ]; then
    CURDIR=$(pwd)
    echo "Installing Dependency Check in ${DIR}..."
    sudo apt install unzip
    mkdir ~/apps
    cd ~/apps && wget $(curl https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep "release.zip" | grep -v asc | grep -v ant | cut -d '' -f 4) -O dependency-check.zip
    unzip dependency-check.zip
    rm dependency-check.zip
    cd $CURDIR      
  fi
}

install_trivy() {
  if ! command -v trivy &> /dev/null
  then
      echo "Installing Trivy ..."
      wget $(curl https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep "Linux-64bit.deb" | cut -d '' -f 4) -O trivy.deb
      sudo dpkg -i trivy.deb
      rm trivy.deb
  fi
}

install_arachni() {
  DIR=~/apps/arachni-1.5.1-0.5.12/
  if [ ! -d "$DIR" ]; then
    CURDIR=$(pwd)
    echo "Installing scanner in ${DIR}..."
    mkdir ~/apps
    cd ~/apps && wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && tar -xvf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
    rm arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
    cd $CURDIR
  fi
}

install_arachni_new() {
  DIR=~/apps/arachni-1.6.1.3-0.6.1.1/
  if [ ! -d "$DIR" ]; then
    CURDIR=$(pwd)
    echo "Installing Arachni 1.6 dependencies..."
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    sudo dpkg -i google-chrome-stable_current_amd64.deb
    sudo apt-get install -f -y
    rm google-chrome-stable_current_amd64.deb
    echo "Installing scanner in ${DIR}..."
    mkdir ~/apps
    cd ~/apps && wget https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz && tar -xvf arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
    rm arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
    cd $CURDIR
  fi
}

echo ""
echo "------ ScanSuite v1.2 -----"
echo "-- Author: Sergey Egorov --"
echo ""

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

  spotbugs)
    container="$repo/spotbugs:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    docker run --rm --volume $(pwd):/src --volume $(pwd):/report $container /analyzer r --target-dir /src --artifact-dir /report --max-depth 10
    upload
    ;;
  
  python)
    container="$repo/bandit:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  eslint)
    container="$repo/eslint:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;
  
  semgrep)
    container="returntocorp/semgrep"
    scan_type='Semgrep JSON Report'
    report_path='semgrep-sast-report.json'
    docker run --rm -v "${PWD}:/src" $container semgrep --config p/owasp-top-ten --json -o $report_path
    upload
    ;;

  php)
    container="$repo/phpcs-security-audit:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  net)
    container="$repo/security-code-scan:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  mobsf)
    container="$repo/mobsf:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  nodejs)
    container="$repo/nodejs-scan:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  go)
    container="$repo/gosec:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  ruby)
    container="$repo/brakeman:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

  cscan)
    container="$repo/flawfinder:latest"
    scan_type='GitLab SAST Report'
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
  
  gitleaks)
    docker run --rm -v $(pwd):/src zricethezav/gitleaks:latest detect -s="/src" -r="/src/gitleaks-report.json"
    scan_type='Gitleaks Scan'
    report_path='gitleaks-report.json'
    upload
    ;;

# Dynamic analyzers

  arachni)
    install_arachni
    ~/apps/arachni-1.5.1-0.5.12/bin/arachni $3 --report-save-path=arachni-report.afr --timeout 2:0:0 --browser-cluster-ignore-images --http-ssl-verify-host --scope-exclude-binaries --checks '*,-*_timing,-backup_files,-common_directories,-backup_directories,-csrf' --output-only-positives --scope-exclude-file-extensions pdf,png,jpg,css,js,gif --scope-page-limit 1000 --scope-dom-depth-limit 1000
    ~/apps/arachni-1.5.1-0.5.12/bin/arachni_reporter arachni-report.afr --reporter=json:outfile=arachni.json
    scan_type='Arachni Scan'
    report_path='arachni.json'
    upload
    ;;

  arachni_new)
    install_arachni_new
    ~/apps/arachni-1.6.1.3-0.6.1.1/bin/arachni $3 --report-save-path=arachni-report.afr --timeout 2:0:0 --browser-cluster-ignore-images --http-ssl-verify-host --scope-exclude-binaries --checks '*,-*_timing,-backup_files,-common_directories,-backup_directories,-csrf' --output-only-positives --scope-exclude-file-extensions pdf,png,jpg,css,js,gif --scope-page-limit 1000 --scope-dom-depth-limit 1000
    ~/apps/arachni-1.6.1.3-0.6.1.1/bin/arachni_reporter arachni-report.afr --reporter=json:outfile=arachni.json
    scan_type='Arachni Scan'
    report_path='arachni.json'
    upload
    ;;

  zap_base)
    docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t $3 -g gen.conf -x zap-report.xml
    scan_type='ZAP Scan'
    report_path='zap-report.xml'
    upload
    ;;

  zap_full)
    docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t $3 -g gen.conf -x zap-report.xml
    scan_type='ZAP Scan'
    report_path='zap-report.xml'
    upload
    ;;

  nikto)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/nikto -h $3 -o /tmp/nikto-output.xml
    scan_type='Nikto Scan'
    report_path='nikto-output.xml'
    upload
    ;;

  sslyze)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/sslyze --regular $3 --json_out /tmp/sslyze-output.json
    scan_type='Sslyze Scan'
    report_path='sslyze-output.json'
    upload
    ;;
  
  dastardly)
    mkdir dastardly && cd dastardly
    docker run --rm --user $(id -u) -v $(pwd):/tmp:rw \
    -e DASTARDLY_TARGET_URL=$2 \
    -e DASTARDLY_OUTPUT_FILE=/tmp/dastardly-report.xml \
    public.ecr.aws/portswigger/dastardly:latest
    mv dastardly-report.xml ../ ; cd .. ; rm -r dastardly/
    cat dastardly-report.xml
    ;;
  
  nuclei)
    docker run --rm -v $(pwd):/tmp projectdiscovery/nuclei:latest -u $3 -silent -json -o /tmp/nuclei-report.json
    scan_type='Nuclei Scan'
    report_path='nuclei-report.json'
    upload
    ;;

  wpscan)
    docker run --rm -v $(pwd):/tmp wpscanteam/wpscan --disable-tls-checks --url $3 -f json -o /tmp/wpscan-report.json
    scan_type='Wpscan'
    report_path='wpscan-report.json'
    upload
    ;;

  nmap)
    docker run --rm -v $(pwd):/tmp --user $(id -u):$(id -g) hysnsec/nmap $3 -oX /tmp/nmap-output.xml
    scan_type='Nmap Scan'
    report_path='nmap-output.xml'
    upload
    ;;

# Dependency checks

  dep_owasp)
    install_dep_owasp
    ~/apps/dependency-check/bin/dependency-check.sh --project test --format XML --scan .
    scan_type='Dependency Check Scan'
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

  # TODO
  # osv_scanner)
  #   docker run --rm -it -v ${PWD}:/src ghcr.io/google/osv-scanner -L /src/pom.xml --json
  #   docker rm $(docker ps -a -q --filter "ancestor=ghcr.io/google/osv-scanner")
  #   ;;

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

# Docker Bench for Security
  docker_bench)
      CURDIR=$(pwd)
      DIR=~/apps/docker-bench-security
      if [ ! -d "$DIR" ]; then
        echo "Installing Docker Bench ..."
        mkdir ~/apps
        cd ~/apps && git clone https://github.com/docker/docker-bench-security.git
      fi
      cd ~/apps/docker-bench-security && sudo sh docker-bench-security.sh
      scan_type='docker-bench-security Scan'
      report_path='log/docker-bench-security.log.json'
      sudo chmod 777 $report_path
      upload
      cd $CURDIR
      ;;

# CIS Kubernetes Benchmark.
  kube_bench)
    docker run --rm --pid=host -v /etc:/etc:ro -v /var:/var:ro -v $(pwd):/tmp -t docker.io/aquasec/kube-bench:latest --json --outputfile /tmp/kube-bench-report.json
    scan_type='kube-bench Scan'
    report_path='kube-bench-report.json'
    upload
    ;;

# Infrastructure as Code.

  iacs_kics)
    container="$repo/kics:latest"
    scan_type='GitLab SAST Report'
    report_path='gl-sast-report.json'
    scan
    ;;

# Trivy checks
  iacs_trivy)
    install_trivy
    echo "DefectDojo doesn't support this scan type. Parse the results manually."
    trivy fs --security-checks config .
    ;;

# Add manual findings

  add_test)
    echo "Adding Manual Test to an Engagement."
    testname=$3
    curl -k -X POST "$dojo_host/api/v2/tests/" -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Token $dojo_apikey" -d "{ \"engagement\": $engagement, \"scan_type\": \"Manual Review\", \"title\": \"$testname\", \"description\": \"$testname\", \"target_start\": \"${date}T13:58:17.580Z\", \"target_end\": \"${future_date}T13:58:17.580Z\", \"lead\": 1, \"test_type\": 7, \"environment\": 3 }"
    ;;

  add_finding)
    echo "Adding Finding to the Test."
    test=$2
    f_name=$3
    f_severity=$4
    f_descr=$5
    f_mitigation=$6
    curl -k -X POST "$dojo_host/api/v2/findings/" -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Token $dojo_apikey"   -d "{ \"test\": $test, \"found_by\": [ 1 ], \"title\": \"$f_name\", \"date\": \"$date\", \"severity\": \"$f_severity\", \"description\": \"$f_descr\", \"mitigation\": \"$f_mitigation\", \"active\": true, \"verified\": false, \"duplicate\": false, \"false_p\": false, \"numerical_severity\": \"S0\"}"
    ;;

# Export arbitrary report types to DefectDojo

  export_report)
    scan_type=$3
    report_path=$4
    upload
    ;;

  *)
    echo "Action or scanner name is unknown for ScanSuite."
    ;;
esac