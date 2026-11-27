### [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
![](https://img.shields.io/static/v1?label=Product&message=Apache%20Log4j2&color=blue)
![](https://img.shields.io/static/v1?label=Version&message=2.0-beta9%20&color=brightgreen)
![](https://img.shields.io/static/v1?label=Vulnerability&message=CWE-20%20Improper%20Input%20Validation&color=brightgreen)
![](https://img.shields.io/static/v1?label=Vulnerability&message=CWE-400%20Uncontrolled%20Resource%20Consumption&color=brightgreen)
![](https://img.shields.io/static/v1?label=Vulnerability&message=CWE-502%20Deserialization%20of%20Untrusted%20Data&color=brightgreen)

### Description

Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

### POC

#### Reference
- http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/165260/VMware-Security-Advisory-2021-0028.html
- http://seclists.org/fulldisclosure/2022/Dec/2
- http://seclists.org/fulldisclosure/2022/Jul/11
- https://github.com/example-owner-9/CVE-mitre/tree/main/CVE-2021-44228
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
- https://www.oracle.com/security-alerts/cpuapr2022.html
- https://www.oracle.com/security-alerts/cpujan2022.html

#### Github
- https://github.com/example-owner-10/CVE-2021-44228
- https://github.com/example-owner-11/5
- https://github.com/example-owner-12/vulnerability-poc
- https://github.com/example-owner-13/Apache-Log4j-POC
- https://github.com/example-owner-14/LogLobster
- https://github.com/example-owner-15/jndisearch
- https://github.com/example-owner-16/OSCP
- https://github.com/example-owner-17/biggest-hack
