import os
import re
import time
import json
import csv
import argparse
import requests
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

def identify_ioc_type(ioc: str) -> str:
    """Identifica si el IOC es IPv4, MD5, SHA1 o SHA256."""
    ioc = ioc.strip()
    # IPv4 regex simple
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ip_regex, ioc):
        return "IP"
    if len(ioc) == 32 and re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "MD5"
    if len(ioc) == 40 and re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "SHA1"
    if len(ioc) == 64 and re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "SHA256"
    return "UNKNOWN"

def check_abuseipdb(ip: str) -> dict:
    """Consulta AbuseIPDB"""
    if not ABUSE_KEY:
        return {"error": "Falta ABUSEIPDB_API_KEY"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSE_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain")
            }
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_hash(file_hash: str) -> dict:
    """Consulta VirusTotal v3 para enriquecer un Hash."""
    if not VT_KEY:
        return {"error": "Falta VT_API_KEY"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "undetected_count": stats.get("undetected", 0)
            }
        elif response.status_code == 404:
            return {"verdict": "No encontrado en VirusTotal"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Enriquecedor de IOCs para SOC Triage")
    parser.add_argument("-f", "--file", required=True, help="Ruta al archivo con lista de IOCs")
    parser.add_argument("-o", "--output", default="ioc_report", help="Nombre base para los reportes de salida")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Error: No se encontró el archivo {args.file}")
        return

    with open(args.file, "r") as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    results = []
    print(f"[*] Iniciando enriquecimiento de {len(iocs)} IOCs...\n")

    for ioc in iocs:
        ioc_type = identify_ioc_type(ioc)
        print(f"[-] Analizando: {ioc} ({ioc_type})")
        
        entry = {
            "ioc": ioc,
            "type": ioc_type,
            "abuseipdb": None,
            "virustotal": None
        }

        if ioc_type == "IP":
            entry["abuseipdb"] = check_abuseipdb(ioc)
            # Respetar rate limits de APIs públicas
            time.sleep(1)
        elif ioc_type in ["MD5", "SHA1", "SHA256"]:
            entry["virustotal"] = check_virustotal_hash(ioc)
            # VirusTotal free permite 4 req/min, una pausa moderada ayuda
            time.sleep(15) 
        else:
            entry["error"] = "Tipo de IOC desconocido"

        results.append(entry)

    # 1. Guardar en JSON
    json_path = f"{args.output}.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=4)
    print(f"\n[+] Reporte JSON guardado en: {json_path}")

    # 2. Guardar resumen plano en CSV
    csv_path = f"{args.output}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(["IOC", "Tipo", "Detalle Amenaza / Score", "ISP / Proveedor", "Error"])
        
        for r in results:
            threat_info = "N/A"
            isp = "N/A"
            error = r.get("error", "")

            if r["abuseipdb"]:
                if "error" in r["abuseipdb"]:
                    error = r["abuseipdb"]["error"]
                else:
                    threat_info = f"Score Abuso: {r['abuseipdb'].get('abuse_confidence_score')}%"
                    isp = r["abuseipdb"].get("isp", "N/A")

            elif r["virustotal"]:
                if "error" in r["virustotal"]:
                    error = r["virustotal"]["error"]
                elif "verdict" in r["virustotal"]:
                    threat_info = r["virustotal"]["verdict"]
                else:
                    mal = r["virustotal"].get("malicious_count", 0)
                    susp = r["virustotal"].get("suspicious_count", 0)
                    threat_info = f"Detecciones VT: {mal} maliciosos / {susp} sospechosos"

            writer.writerow([r["ioc"], r["type"], threat_info, isp, error])

    print(f"[+] Reporte CSV guardado en: {csv_path}")

if __name__ == "__main__":
    main()