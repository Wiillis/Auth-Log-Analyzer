import re
import requests
from collections import Counter

# Configuration
LOG_FILE = "auth.log"  # Simule le fichier de log Linux
THRESHOLD = 5          # Nombre d'échecs avant alerte
ABUSEIPDB_API_KEY = "TON_API_KEY_ICI" # Optionnel pour l'enrichissement

def analyze_brute_force():
    failed_attempts = []
    
    # Expression régulière pour trouver les échecs de connexion SSH
    # Exemple de ligne : Dec 31 14:20:01 server sshd[1234]: Failed password for root from 192.168.1.50
    regex = r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                match = re.search(regex, line)
                if match:
                    failed_attempts.append(match.group(1))
    except FileNotFoundError:
        print(f"[!] Erreur : Le fichier {LOG_FILE} est introuvable.")
        return

    # Compter les échecs par adresse IP
    stats = Counter(failed_attempts)
    
    print(f"--- Rapport d'Analyse de Sécurité ---")
    for ip, count in stats.items():
        if count >= THRESHOLD:
            print(f"[ALERTE] Force Brute détectée : {ip} ({count} tentatives)")
            # Optionnel : check_ip_reputation(ip)

def check_ip_reputation(ip):
    """Vérifie la réputation de l'IP via l'API AbuseIPDB"""
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        print(f"    -> Score de réputation AbuseIPDB : {score}%")

if __name__ == "__main__":
    analyze_brute_force()
