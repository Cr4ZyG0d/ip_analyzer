# IP Analyzer

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

> Herramienta avanzada para análisis de IPs: geolocalización, WHOIS, RDAP, puertos abiertos y más.

## 🚀 Descripción
**IP Analyzer** es un script en Python que permite analizar una o varias direcciones IP, obteniendo información relevante como:
* Estado de conectividad (ping)
* Geolocalización (país, ciudad, ISP, organización, ASN, lat/lon)
* DNS inverso (PTR)
* Información WHOIS y RDAP fusionada (registrar, organización, nombre, creación)
* Escaneo rápido de puertos comunes

Ideal para tareas de auditoría, pentesting, administración de redes o simplemente curiosidad técnica.

---

## 🛠️ Instalación

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/Cr4ZyG0d/ip_analyzer.git
    cd ip-analyzer
    ```

2.  **Instala las dependencias:**
    ```bash
    pip install -r requirements.txt
    ```
    O instala manualmente:
    ```bash
    pip install requests ipwhois
    ```

3.  **(Opcional)** Asegúrate de tener instalado el comando `whois` en tu sistema:
    * En Debian/Ubuntu/Kali:
        ```bash
        sudo apt install whois
        ```

---

## ⚡ Uso rápido

* **Analizar IPs desde archivo:**
    ```bash
    python3 ip_analyzer.py -f list_ip.txt
    ```

* **Analizar IPs desde línea de comandos:**
    ```bash
    python3 ip_analyzer.py -i 8.8.8.8 1.1.1.1
    ```

* **Guardar resultados en CSV:**
    ```bash
    python3 ip_analyzer.py -f list_ip.txt -o result.csv
    ```

---

## 📋 Ejemplo de salida

| IP | Estado | Pais | Ciudad | ISP | Org Geo | ASN | Lat/Lon | PTR | Registrar | Org WHOIS | Nombre | Creacion | Puertos abiertos |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 8.8.8.8 | Conectado | United States | Mountain View | Google LLC | Google LLC | AS15169 | 37.386,-122.083 | dns.google | arin | Google LLC | Google | 1996-10-10 | 53,80,443 |

*Export as CSV*

---

## 🧩 Opciones

* `-f`, `--file`: Archivo con IPs (una por línea)
* `-i`, `--ips`: Lista de IPs separadas por espacio
* `-o`, `--output`: Archivo de salida en CSV

---

## 🤝 Contribuciones
¡Las contribuciones son bienvenidas!
Puedes abrir issues, enviar pull requests o sugerencias.

---

## 📄 Licencia
[MIT License](https://opensource.org/licenses/MIT)

---

## ✨ Autor
Desarrollado por **Cr4ZyG0d**
