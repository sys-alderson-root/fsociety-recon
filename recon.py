import socket
import urllib.request
import json
import ssl
import os
import sys

BANNER = """
    ___________                 __  _          
   / ____/ ___/ /___  ____  _____/ /_(_)__  __  
  / /_   \__ \/ / __ \/ __ \/ ___/ __/ / _ \/ /  
 / __/  ___/ / / /_/ / / / / /__/ /_/ /  __/ /   
/_/    /____/_/\____/_/ /_/\___/\__/_/\___/_/    
                                                 
 [ fs0ciety // OSINT RECON TOOL ]
===================================================
"""

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def menu():
    print(BANNER)
    print(" [ 1 ] Résolution DNS & IP (Trouver l'IP d'un domaine)")
    print(" [ 2 ] Géolocalisation d'une IP publique")
    print(" [ 3 ] Audit SSL/TLS (Certificat d'un site)")
    print(" [ 4 ] Quitter fsociety")
    return input("\n[root@fsociety:~]# ")

def resolve_dns():
    domain = input("\n[?] Entrez un nom de domaine (ex: google.com) : ").strip()
    if not domain:
        return
    try:
        print(f"\n[*] Résolution de {domain} en cours...")
        ip = socket.gethostbyname(domain)
        print(f"[+] L'adresse IP de {domain} est : {ip}")
        
        # Essai de récupération du nom d'hôte inverse
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            print(f"[+] Nom d'hôte inverse : {hostname}")
        except:
            print("[-] Pas de nom d'hôte inverse (PTR) trouvé.")
            
    except socket.gaierror:
        print(f"\n[-] ERREUR : Impossible de résoudre {domain}.")
    input("\n[>] Appuie sur Entrée pour retourner au terminal...")

def geo_ip():
    ip = input("\n[?] Entrez une adresse IP publique (ex: 8.8.8.8) : ").strip()
    if not ip:
        return
    try:
        # API gratuite et publique pour la géolocalisation d'IP
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            if data.get("status") == "success":
                print(f"\n[+] Informations pour l'IP {ip} :")
                print(f"    Pays       : {data.get('country')}")
                print(f"    Région     : {data.get('regionName')}")
                print(f"    Ville      : {data.get('city')}")
                print(f"    FAI (ISP)  : {data.get('isp')}")
                print(f"    Organisation: {data.get('org')}")
            else:
                print("\n[-] ERREUR : IP invalide ou informations introuvables.")
    except Exception as e:
        print(f"\n[-] ERREUR : {e}")
    input("\n[>] Appuie sur Entrée pour retourner au terminal...")

def ssl_audit():
    domain = input("\n[?] Entrez le domaine à auditer (ex: github.com) : ").strip()
    if not domain:
        return
    try:
        print(f"\n[*] Connexion sécurisée à {domain}:443...")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                print(f"[+] Certificat SSL valide pour {domain}")
                print(f"    Émetteur   : {issuer.get('organizationName', 'Inconnu')}")
                print(f"    Sujet (CN) : {subject.get('commonName', 'Inconnu')}")
                print(f"    Expire le  : {cert['notAfter']}")
                print(f"    Protocole  : {tls_sock.version()}")
    except ssl.SSLCertVerificationError:
        print(f"\n[-] ERREUR : Le certificat SSL de {domain} est invalide !")
    except Exception as e:
        print(f"\n[-] ERREUR : Impossible d'auditer {domain}. ({e})")
    input("\n[>] Appuie sur Entrée pour retourner au terminal...")

def main():
    while True:
        clear()
        choix = menu()
        if choix == "1":
            resolve_dns()
        elif choix == "2":
            geo_ip()
        elif choix == "3":
            ssl_audit()
        elif choix == "4":
            print("\n[i] Déconnexion de fsociety... Au revoir, friend.")
            break
        else:
            print("\n[-] Commande inconnue.")
            input("[>] Appuie sur Entrée...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Interrompu.")
        sys.exit()
