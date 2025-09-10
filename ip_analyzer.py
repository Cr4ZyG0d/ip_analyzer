#!/usr/bin/env python3
import argparse
import subprocess
import requests
import socket
import csv
from datetime import datetime
from ipwhois import IPWhois

def ping(ip):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '2', ip], stderr=subprocess.STDOUT)
        return "Conectado"
    except subprocess.CalledProcessError:
        return "Sin conexión"

def get_geoinfo(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon"
        r = requests.get(url, timeout=5)
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Desconocido"),
                "regionName": data.get("regionName", "Desconocido"),
                "city": data.get("city", "Desconocido"),
                "isp": data.get("isp", "Desconocido"),
                "org": data.get("org", "Desconocido"),
                "asn": data.get("as", "Desconocido"),
                "latlon": f"{data.get('lat','')},{data.get('lon','')}"
            }
        else:
            return {k: "Desconocido" for k in ["country","regionName","city","isp","org","asn","latlon"]}
    except Exception:
        return {k: "Desconocido" for k in ["country","regionName","city","isp","org","asn","latlon"]}

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Desconocido"

def get_ipwhois(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        network = res.get("network", {})
        return {
            "name": network.get("name", ""),
            "org": network.get("remarks", [""])[0] if network.get("remarks") else "",
            "creation": network.get("events", [{}])[0].get("date", "") if network.get("events") else "",
            "registrar": res.get("asn_registry", ""),
        }
    except Exception:
        return {
            "name": "",
            "org": "",
            "creation": "",
            "registrar": "",
        }

def get_whois(ip):
    try:
        output = subprocess.check_output(['whois', ip], stderr=subprocess.STDOUT, universal_newlines=True, timeout=10)
        data = {}
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                if key in ['orgname', 'organization', 'owner', 'netname', 'descr', 'responsible']:
                    data['name'] = value
                elif key in ['created', 'creation date', 'registered', 'regdate']:
                    data['creation'] = value
                elif key in ['registrar']:
                    data['registrar'] = value
        return data
    except Exception:
        return {}

def merge_whois_data(whois_data, ipwhois_data):
    """Fusiona datos de WHOIS y RDAP/IPWhois de forma robusta."""
    def pick(*fields):
        for f in fields:
            if isinstance(f, list) and f:
                f = f[0]
            if isinstance(f, dict):
                f = f.get('description', '') or f.get('name', '') or str(f)
            if isinstance(f, str) and f.strip() and f.strip().lower() != 'desconocido':
                return f.strip()
            elif f and str(f).strip().lower() != 'desconocido':
                return str(f).strip()
        return "Desconocido"
    
    return {
        "name": pick(whois_data.get("name", ""), ipwhois_data.get("name", "")),
        "creation": pick(whois_data.get("creation", ""), ipwhois_data.get("creation", "")),
        "registrar": pick(whois_data.get("registrar", ""), ipwhois_data.get("registrar", "")),
        "org": pick(ipwhois_data.get("org", ""), whois_data.get("org", "")),
    }

def scan_ports(ip, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5900, 8080, 8081]):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(str(port))
        except Exception:
            continue
    return ",".join(open_ports) if open_ports else "Ninguno"

def parse_ips(args):
    if args.file:
        with open(args.file) as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return args.ips
       
COLORS = [
    '\033[1;37m',  # IP - Blanco brillante
    '\033[1;32m',  # Estado - Verde
    '\033[1;34m',  # País - Azul
    '\033[1;36m',  # Ciudad - Cian
    '\033[1;35m',  # ISP - Magenta
    '\033[1;33m',  # Org Geo - Amarillo
    '\033[1;31m',  # ASN - Rojo
    '\033[0;36m',  # Lat/Lon - Cian claro
    '\033[1;30m',  # PTR - Gris
    '\033[0;35m',  # Registrar - Magenta claro
    '\033[0;33m',  # Org WHOIS - Amarillo claro
    '\033[0;32m',  # Nombre - Verde claro
    '\033[0;34m',  # Creacion - Azul claro
    '\033[0;31m',  # Puertos abiertos - Rojo claro
]
RESET = '\033[0m'

def print_colored_row(row):
    colored = []
    for i, val in enumerate(row):
        color = COLORS[i % len(COLORS)]
        colored.append(f"{color}{val}{RESET}")
    print(" | ".join(colored))

def main():
    parser = argparse.ArgumentParser(description="Analizador avanzado de IPs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='Archivo con IPs')
    group.add_argument('-i', '--ips', nargs='+', help='IPs separadas por espacio')
    parser.add_argument('-o', '--output', type=str, help='Archivo de salida (CSV)')
    args = parser.parse_args()

    ips = parse_ips(args)
    headers = [
        "IP", "Estado", "Pais", "Ciudad", "ISP", "Org Geo", "ASN", "Lat/Lon",
        "PTR", "Registrar", "Org WHOIS", "Nombre", "Creacion", "Puertos abiertos"
    ]
    results = []

    for ip in ips:
        estado = ping(ip)
        geo = get_geoinfo(ip)
        ptr = reverse_dns(ip)
        ipwhois_data = get_ipwhois(ip)
        whois_data = get_whois(ip)
        merged = merge_whois_data(whois_data, ipwhois_data)
        ports = scan_ports(ip)

        row = [
            ip,
            estado,
            geo["country"],
            geo["city"],
            geo["isp"],
            geo["org"],
            geo["asn"],
            geo["latlon"],
            ptr,
            merged["registrar"],
            merged["org"],
            merged["name"],
            merged["creation"],
            ports
        ]
        row = [str(x) if x is not None else "Desconocido" for x in row]
        results.append(row)

    if args.output:
        with open(args.output, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(results)
        print(f"Resultados guardados en {args.output}")
    else:
        print_colored_row(headers)
        for row in results:
            print_colored_row(row)

if __name__ == "__main__":
    main()
