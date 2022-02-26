
### Static and Dynamic Security Analysis with ScanSuite 

ScanSuite is the bash wrapper around the code (SAST), Infrastructure as Code (IACS), Containers and dependency (SCA) analysis tools. It also invokes dynamic scans (DAST).
Leverages [GitLab](https://docs.gitlab.com/ee/user/application_security/sast/) Docker images as well as other known open source tools. To run most of the scans you'll need to have Docker installed.

Results are exported to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (fill in the IP and api key inside the script). Ensure you have it installed.

#### Prepare the DefectDojo

Create a new Product in DefectDojo:

```
scansuite.sh init_product <App Name>
Example: ~/scansuite.sh init_product SomeCoolApp
```

Take a note of created "id" of the product from the output. Create an Engagement within the Product:

```
scansuite.sh init_engage <Product id>        
Example: ~/scansuite.sh init_engage 2
```

Once created, take a note of "id" of Engagement. You'll need to provide it during the scans.

#### SAST scanners:

Start the scan from the source code folder.

```
cd SomeCoolApp
scansuite.sh <scanner name> <Engagement id> 
```
Here the `scanner name` is the keyword. Choose from the one of the following:

* python      - Bandit Python code scan
* java        - SpotBugs Java, Kotlin, Groovy, Scala code scan. Works with Ant, Gradle, Maven, and SBT build systems.
* eslint      - ESLint JavaScript and React scan.
* semgrep     - C#, Go, Java, JavaScript, JSX, JSON, Python, Ruby, TypeScript, TSX
* php         - PHP CS security-audit
* net         - .NET Security Code Scan
* nodejs      - NodeJsScan
* go          - Gosec Go scan
* ruby        - Brakeman Ruby scan
* mobsf       - Android/ Kotlin
* cscan       - Flawfinder C/C++
* secrets     - Checking for hardcoded passwords, API keys etc

```
Example: ~/scansuite.sh python 3
```

#### Docker image checks:

[Trivy](https://github.com/aquasecurity/trivy) Docker image scan. Requires the image name with the tag.

```
Example: ~/scansuite.sh image_trivy 3 vulnerables/web-dvwa:latest                  
```

#### Dependency checks:

Start the scan from the source code folder.

```
cd SomeCoolApp
scansuite.sh <scanner name> <Engagement id> 
```

* gemnasium   - Supports [many languages](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/)
* gemnasium_python - Checks Python dependencies in requirements.txt file
* retire      - Retire JS checks NodeJS/ npm dependencies.
* dep_trivy   - Trivy dependency checks.
* dep_owasp   - OWASP Dependency Check. Supports lots of languages.

#### DAST scan:

```
scansuite.sh <scanner name> <Engagement id> <URL>
```

* nikto       - Nikto scan. Example: ~/scansuite.sh nikto 3 https://google.com
* sslyze      - SSL checks. Example: ~/scansuite.sh sslyze 3 google.com:443
* arachni     - Ensure you have it in your home path:

```
Example: ~/scansuite.sh arachni 3 https://google.com
```

#### IACS (Infrastructure as Code) scan:

Start the scan from the source code folder.

```
cd SomeCoolApp
scansuite.sh iacs_kics <Engagement id> 
```

* iacs_kics - Checkmarx KICS scanner for Ansible, AWS CloudFormation, Kubernetes, Terraform, Docker
* iacs_trivy - Trivy checks for config files and dependencies.

Once the scan is performed and uploaded to DefectDojo, login there and check the results.