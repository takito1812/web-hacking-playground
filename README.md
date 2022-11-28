# Web Hacking Playground

## Description

Web Hacking Playground is a controlled web hacking environment. It consists of vulnerabilities found in real cases, both in pentests and in Bug Bounty programs. The objective is that users can practice with them, and learn to detect and exploit them.

Other topics of interest will also be addressed, such as: bypassing filters by creating custom payloads, executing chained attacks exploiting various vulnerabilities, developing proof-of-concept scripts, among others.

### Important

The application source code is visible. However, the lab's approach is a black box one. Therefore, the code should not be reviewed to resolve the challenges.

Additionally, it should be noted that fuzzing (both parameters and directories) and brute force attacks do not provide any advantage in this lab.

## Setup

It is recommended to use [Kali Linux](https://www.kali.org/get-kali/) to perform this lab. In case of using a virtual machine, it is advisable to use the [VMware Workstation Player](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html) hypervisor.

The environment is based on Docker and Docker Compose, so it is necessary to have both installed.

To install Docker on Kali Linux, run the following commands:

    sudo apt update -y
    sudo apt install -y docker.io
    sudo systemctl enable docker --now
    sudo usermod -aG docker $USER

To install Docker on other Debian-based distributions, run the following commands:

    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo systemctl enable docker --now
    sudo usermod -aG docker $USER

It is recommended to log out and log in again so that the user is recognized as belonging to the docker group.

To install Docker Compose, run the following command:

    sudo apt install -y docker-compose

**Note:** In case of using M1 it is recommended to execute the following command before building the images:

    export DOCKER_DEFAULT_PLATFORM=linux/amd64

The next step is to clone the repository and build the Docker images:

    git clone https://github.com/takito1812/web-hacking-playground.git
    cd web-hacking-playground
    docker-compose build

Also, it is recommended to install the [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) browser extension, which allows you to easily change proxy settings, and [Burp Suite](https://portswigger.net/burp/communitydownload), which we will use to intercept HTTP requests.

We will create a new profile in Foxy Proxy to use Burp Suite as a proxy. To do this, we go to the Foxy Proxy options, and add a proxy with the following configuration:

* **Proxy Type:** HTTP
* **Proxy IP address:** 127.0.0.1
* **Port:** 8080

## Deployment

Once everything you need is installed, you can deploy the environment with the following command:

    git clone https://github.com/takito1812/web-hacking-playground.git
    cd web-hacking-playground
    docker-compose up -d

This will create two containers of applications developed in Flask on port 80:

* **The vulnerable web application (Socially)**: Simulates a social network.
* **The exploit server:** You should not try to hack it, since it does not have any vulnerabilities. Its objective is to simulate a victim's access to a malicious link.

### Important

It is necessary to add the IP of the containers to the /etc/hosts file, so that they can be accessed by name and that the exploit server can communicate with the vulnerable web application. To do this, run the following commands:

    sudo sed -i '/whp-/d' /etc/hosts
    echo "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' whp-socially) whp-socially" | sudo tee -a /etc/hosts
    echo "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' whp-exploitserver) whp-exploitserver" | sudo tee -a /etc/hosts

Once this is done, the vulnerable application can be accessed from http://whp-socially and the exploit server from http://whp-exploitserver.

When using the exploit server, the above URLs must be used, using the domain name and not the IPs. This ensures correct communication between containers.

When it comes to hacking, to represent the attacker's server, the local Docker IP must be used, since the lab is not intended to make requests to external servers such as Burp Collaborator, Interactsh, etc. A Python http.server can be used to simulate a web server and receive HTTP interactions. To do this, run the following command:

    sudo python3 -m http.server 80

## Stages

The environment is divided into three stages, each with different vulnerabilities. It is important that they are done in order, as the vulnerabilities in the following stages build on those in the previous stages. The stages are:

* **Stage 1:** Access with any user
* **Stage 2:** Access as admin
* **Stage 3:** Read the /flag file

### Important

Below are spoilers for each stage's vulnerabilities. If you don't need help, you can skip this section. On the other hand, if you don't know where to start, or want to check if you're on the right track, you can extend the section that interests you.

### Stage 1: Access with any user

<details>
<summary>Display</summary>

At this stage, a specific user's session can be stolen through Cross-Site Scripting (XSS), which allows JavaScript code to be executed. To do this, the victim must be able to access a URL in the user's context, this behavior can be simulated with the exploit server.

The hints to solve this stage are:

* Are there any striking posts on the home page?
* You have to chain two vulnerabilities to steal the session. XSS is achieved by exploiting an Open Redirect vulnerability, where the victim is redirected to an external URL.
* The Open Redirect has some security restrictions. You have to find how to get around them. Analyze which strings are not allowed in the URL.
* Cookies are not the only place where session information is stored. Reviewing the source code of the JavaScript files included in the application can help clear up doubts.

</details>

### Stage 2: Access as admin

<details>
<summary>Display</summary>

At this stage, a token can be generated that allows access as admin. This is a typical JSON Web Token (JWT) attack, in which the token payload can be modified to escalate privileges.

The hint to solve this stage is that there is an endpoint that, given a JWT, returns a valid session cookie.

</details>

### Stage 3: Read the /flag file

<details>
<summary>Display</summary>

At this stage, the /flag file can be read through a Server Site Template Injection (SSTI) vulnerability. To do this, you must get the application to run Python code on the server. It is possible to execute system commands on the server.

The hints to solve this stage are:

* Vulnerable functionality is protected by two-factor authentication. Therefore, before exploiting the SSTI, a way to bypass the OTP code request must be found. There are times when the application trusts the requests that are made from the same server and the HTTP headers play an important role in this situation.
* The SSTI is Blind, this means that the output of the code executed on the server is not obtained directly. The Python smtpd module allows you to create an SMTP server that prints messages it receives to standard output:

    `sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25`

* The application uses Flask, so it can be inferred that the template engine is Jinja2 because it is recommended by the official Flask documentation and is widely used. You must get a Jinja2 compatible payload to get the final flag.
* The email message has a character limitation. Information on how to bypass this limitation can be found on the Internet.

</details>

## Solutions

Detailed solutions for each stage can be found in the [Solutions](https://github.com/takito1812/web-hacking-playground/tree/main/Solutions) folder.

## Resources

The following resources may be helpful in resolving the stages:

* [Google](https://www.google.com/)
* [Twitter Advanced Search](https://twitter.com/search-advanced)
* [HackTricks](https://book.hacktricks.xyz/)
* [PortSwigger Learning Materials](https://portswigger.net/web-security/all-materials)
* [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [Payload Box](https://github.com/payloadbox)

## Collaboration

Pull requests are welcome. If you find any bugs, please open an issue.
