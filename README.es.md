# Web Hacking Playground

## Descripción

Web Hacking Playground es un entorno controlado de hacking web. Consta de vulnerabilidades encontradas en casos reales, tanto en pentests como en programas de Bug Bounty. El objetivo es que los usuarios puedan practicar con ellas, y aprender a detectarlas y explotarlas.

También se abordarán otros temas de interés como: evadir filtros creando payloads personalizados, ejecutar ataques encadenados explotando varias vulnerabilidades, desarrollar scripts de prueba de concepto, entre otros.

### Importante

El código fuente de la aplicación es visible. Sin embargo, el enfoque del laboratorio es de caja negra. Por tanto, el código no debe ser revisado para resolver los retos.

Adicionalmente, cabe destacar que el fuzzing (tanto de parámetros como de directorios) y los ataques de fuerza bruta no brindan ninguna ventaja en este laboratorio.

## Instalación

Se recomienda utilizar [Kali Linux](https://www.kali.org/get-kali/) para realizar este laboratorio. En caso de utilizar una máquina virtual, se aconseja utilizar el hipervisor [VMware Workstation Player](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html).

El entorno está basado en Docker y Docker Compose, por lo que es necesario tener instalados ambos.

Para instalar Docker en Kali Linux, ejecutar los siguientes comandos:

    sudo apt update -y
    sudo apt install -y docker.io
    sudo systemctl enable docker --now

Para instalar Docker en otras distribuciones basadas en Debian, ejecutar los siguientes comandos:

    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo systemctl enable docker --now

Para instalar Docker Compose, ejecutar el siguiente comando:

    sudo apt install -y docker-compose

**Nota:** En caso de usar M1 se recomienda ejecutar el siguiente comando antes de construir las imágenes:

    export DOCKER_DEFAULT_PLATFORM=linux/amd64

El siguiente paso es clonar el repositorio y construir las imágenes de Docker:

    git clone https://github.com/takito1812/web-hacking-playground.git
    cd web-hacking-playground
    docker-compose build

Además, se recomienda instalar la extensión de navegador [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/), que permite fácilmente cambiar la configuración del proxy, y [Burp Suite](https://portswigger.net/burp/communitydownload), que usaremos para interceptar las peticiones HTTP.

Crearemos un nuevo perfil en Foxy Proxy para usar Burp Suite como proxy. Para ello, vamos a las opciones de Foxy Proxy, y agregamos un proxy con la siguiente configuración:

* **Proxy Type:** HTTP
* **Proxy IP address:** 127.0.0.1
* **Port:** 8080

## Despliegue

Una vez instalado todo lo necesario, se puede desplegar el entorno con el siguiente comando:

    docker-compose up -d

Esto creará dos contenedores de aplicaciones desarrolladas en Flask en el puerto 80:

* **La aplicación web vulnerable (Socially)**: Simula una red social.
* **El servidor de explotación:** No hay que intentar hackearlo, ya que no tiene ninguna vulnerabilidad. Su objetivo es simular el acceso de una víctima a un enlace malicioso.

### Importante

Es necesario añadir la IP de los contenedores al fichero /etc/hosts, para que se puedan acceder a ellos por su nombre y que el servidor de explotación pueda comunicarse con la aplicación web vulnerable. Para ello, ejecutar los siguientes comandos:

    sudo sed -i '/whp-/d' /etc/hosts
    echo "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' whp-socially) whp-socially" | sudo tee -a /etc/hosts
    echo "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' whp-exploitserver) whp-exploitserver" | sudo tee -a /etc/hosts

Una vez hecho esto, ya se puede acceder a la aplicación vulnerable desde http://whp-socially y al servidor de explotación desde http://whp-exploitserver.

Al utilizar el servidor de explotación, se deben emplear las URL anteriores, utilizando el nombre de dominio y no las IPs. Esto asegura la correcta comunicación entre los contenedores.

A la hora de hackear, para representar el servidor del atacante, se debe utilizar la IP local de Docker, dado que el laboratorio no está ideado para realizar peticiones a servidores externos como los de Burp Collaborator, Interactsh, etc. Un http.server de Python puede ser utilizado para simular un servidor web y recibir las interacciones HTTP. Para ello, ejecutar el siguiente comando:

    sudo python3 -m http.server 80

## Etapas

El entorno está dividido en tres etapas, cada una con vulnerabilidades diferentes. Es importante que se realicen en orden, ya que las vulnerabilidades de las etapas siguientes se basan en las de las etapas anteriores. Las etapas son:

* **Etapa 1:** Acceder con cualquier usuario
* **Etapa 2:** Acceder como admin
* **Etapa 3:** Leer el archivo /flag

### Importante

A continuación hay spoilers de las vulnerabilidades de cada etapa. Si no necesitas ayuda, puedes saltarte esta sección. En cambio, si no sabes por dónde empezar, o quieres comprobar si vas por el buen camino, puedes extender la sección que te interese.

### Etapa 1: Acceder con cualquier usuario

<details>
<summary>Mostrar</summary>

En esta etapa, se puede robar la sesión de un usuario concreto a través de un Cross-Site Scripting (XSS), que permite ejecutar código JavaScript. Para ello, se debe conseguir que la víctima acceda a una URL en el contexto del usuario, este comportamiento se puede simular con el servidor de explotación.

Las pistas para resolver esta etapa son:

* ¿Hay algún post llamativo en la página principal?
* Hay que encadenar dos vulnerabilidades para robar la sesión. El XSS se consigue aprovechando una vulnerabilidad de Open Redirect, en la que se redirige a la víctima a una URL externa.
* El Open Redirect cuenta con algunas restricciones de seguridad. Hay que encontrar cómo saltárselas. Analiza que strings no se permiten en la URL.
* Las cookies no son el único lugar donde se almacena la información relativa a la sesión. Revisar el código fuente de los archivos JavaScript incluidos en la aplicación puede ayudar a zanjar dudas.

</details>

### Etapa 2: Acceder como admin

<details>
<summary>Mostrar</summary>

En esta etapa, se puede generar un token que permite acceder como admin. Es un ataque típico de JSON Web Token (JWT), en el que se puede modificar el payload del token para escalar privilegios.

Las pista para resolver esta etapa es que existe un endpoint que dado un JWT, devuelve una cookie de sesión válida.

</details>

### Etapa 3: Leer el archivo /flag

<details>
<summary>Mostrar</summary>

En esta etapa, se puede leer el archivo /flag a través de una vulnerabilidad de Server Site Template Injection (SSTI). Para ello, se debe conseguir que la aplicación ejecute código Python en el servidor. Es posible llegar a ejecutar comandos de sistema en el servidor.

Las pistas para resolver esta etapa son:

* La funcionalidad vulnerable se encuentra protegida por un doble factor de autenticación. Por tanto, antes de explotar el SSTI, hay que conseguir una forma de saltarse la solicitud del código OTP. Hay veces que la aplicación confía en las peticiones que se hacen desde el mismo servidor y las cabeceras HTTP juegan un papel importante en esta situación.
* El SSTI es Blind, esto quiere decir que la salida del código ejecutado en el servidor no se obtiene directamente. El módulo smtpd de Python permite crear un servidor SMTP que imprime en la salida estándar los mensajes que recibe:

    `sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25`

* La aplicación usa Flask, por tanto, se puede deducir que el motor de plantillas es Jinja2 porque es recomendado por la documentación oficial de Flask y es ampliamente utilizado. Se debe conseguir un payload compatible con Jinja2 para conseguir la flag final.
* El mensaje de correo electrónico cuenta con una limitación de caracteres. En Internet, se puede encontrar información sobre cómo saltarse esta limitación.

</details>

## Soluciones

En la carpeta [Solutions](https://github.com/takito1812/web-hacking-playground/tree/main/Solutions) se encuentran las soluciones detalladas de cada etapa.

## Recursos

Los siguientes recursos pueden ser de ayuda para resolver las etapas:

* [Google](https://www.google.com/)
* [Twitter Advanced Search](https://twitter.com/search-advanced)
* [HackTricks](https://book.hacktricks.xyz/)
* [PortSwigger Learning Materials](https://portswigger.net/web-security/all-materials)
* [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [Payload Box](https://github.com/payloadbox)

## Colaboración

Los pull requests son bienvenidos. Si encuentras algún bug, por favor, abre un issue.
