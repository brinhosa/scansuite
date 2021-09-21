
### Static and Dynamic Security Analysis with ScanSuite 

ScanSuite is the bash wrapper for the code (SAST) and dependency (OAST) analysis tools. It also invokes dynamic websites scans (DAST).
Leverages GitLab Docker images as well as other known open source tools. To run most of the scans you'll need to have Docker installed.

Results are exported to DefectDojo (fill in the IP, api key and csrf token inside the script).

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
* java        - SpotBugs Java code scan. Will build your code before scan, works with Ant, Gradle, Maven, and SBT build systems.
* js_eslint   - ESLint JavaScript scan
* js_semgrep  - Semgrep JavaScript scan
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

#### Container checks:

Trivy container scan. Requires the image name with the tag. Get it installed first:

```
wget https://github.com/aquasecurity/trivy/releases/download/v0.19.2/trivy_0.19.2_Linux-64bit.deb && sudo dpkg -i trivy_0.19.2_Linux-64bit.deb
scansuite.sh container <Engagement id> <Container Name>

Example: ~/scansuite.sh container 3 vulnerables/web-dvwa:latest                  
```

#### Dependency checks:

Start the scan from the source code folder.

```
cd SomeCoolApp
scansuite.sh <scanner name> <Engagement id> 
```

* safety      - Checks Python dependencies in requirements.txt file
* gemnasium   - Supports many languages
* retire      - Retire JS checks NodeJS/ npm dependencies.
* dep_check   - OWASP Dependency Check. Supports many languages. As this is not a docker, you'll need to exctract it to your home folder:

```
cd && wget https://github.com/jeremylong/DependencyCheck/releases/download/v6.1.6/dependency-check-6.1.6-release.zip && unzip dependency-check-6.1.6-release.zip
```

#### DAST scan:

```
scansuite.sh <scanner name> <Engagement id> <URL>
```

* nikto       - Nikto scan. Example: ~/scansuite.sh nikto 3 https://google.com
* sslyze      - SSL checks. Example: ~/scansuite.sh sslyze 3 google.com:443
* arachni     - Ensure you have it in your home path:

```
cd && wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && tar -xvf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
Example: ~/scansuite.sh arachni 3 https://google.com
```

Once the scan is performed and uploaded to DefectDojo, login there and check the results.

### External References:

* https://docs.gitlab.com/ee/user/application_security/sast/
* https://docs.gitlab.com/ee/user/application_security/dependency_scanning/