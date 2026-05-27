# OSINT Harvester

Outil OSINT passif inspire de `theHarvester`, pense comme un projet portfolio cyber : collecte multi-sources, scoring de risque, rapports HTML/Markdown/JSON/CSV et comparaison entre deux executions.

## Ce que l'outil fait

- Collecte de sous-domaines depuis Certificate Transparency, Wayback, urlscan et HackerTarget.
- Collecte DNS publique via DNS-over-HTTPS.
- Detection SPF, DMARC, MX et CAA.
- Extraction d'emails trouves dans les URLs, DNS/TXT et documents publics.
- Inventaire de documents publics indexes.
- Extraction de metadonnees PDF et Office Open XML lorsque les documents sont accessibles.
- Score de risque explicable avec constats priorises et recommandations.
- Export `report.html`, `report.md`, `report.json` et CSV.
- Mode `--compare` pour suivre les nouveaux sous-domaines, emails, documents et changements DNS.

## Cadre d'utilisation

Utiliser uniquement sur un domaine que vous possedez, administrez, ou pour lequel vous avez une autorisation explicite.

L'outil est volontairement passif :

- pas de scan de ports ;
- pas de brute force ;
- pas de tentative de connexion ;
- pas d'exploitation de faille ;
- pas de contournement d'authentification.

Il interroge uniquement des sources publiques et des archives.

## Lancement rapide

Depuis la racine du projet :

```powershell
python .\osint_harvester.py example.com --limit 50 --metadata-limit 0
```

Avec extraction de metadonnees sur quelques documents archives :

```powershell
python .\osint_harvester.py example.com --limit 100 --metadata-limit 3
```

Limiter les sources :

```powershell
python .\osint_harvester.py example.com --sources crtsh,dns,wayback
```

Choisir le dossier de sortie :

```powershell
python .\osint_harvester.py example.com --out .\reports\example-demo
```

Comparer deux executions :

```powershell
python .\osint_harvester.py --compare .\reports\old\report.json .\reports\new\report.json --out .\reports\compare-demo
```

## Sorties generees

Le dossier de sortie contient :

- `report.html` : tableau de bord lisible dans un navigateur ;
- `report.md` : rapport Markdown pour rendu ou GitHub ;
- `report.json` : donnees structurees completes ;
- `subdomains.csv` : sous-domaines et sources ;
- `emails.csv` : emails et sources ;
- `dns_records.csv` : enregistrements DNS publics ;
- `documents.csv` : documents publics et metadonnees extraites ;
- `risk_findings.csv` : constats de risque priorises.

Le mode comparaison genere :

- `comparison.html` ;
- `comparison.md` ;
- `comparison.json`.

## Sources disponibles

```text
crtsh        Certificate Transparency logs
dns          DNS publics via https://dns.google/resolve
wayback      Internet Archive CDX
urlscan      API publique urlscan.io
hackertarget API publique HackerTarget hostsearch
```

La valeur par defaut `all` active toutes les sources ci-dessus.

## Scoring de risque

Le score est volontairement explicable. Chaque point vient d'un constat affiche dans `risk_findings.csv`, `report.md` et `report.html`.

Exemples de signaux :

- SPF absent ou trop permissif ;
- DMARC absent ou seulement en monitoring ;
- CAA absent ;
- emails publics ;
- documents publics ;
- metadonnees nominatives dans des PDF ou fichiers Office ;
- sous-domaines sensibles comme `admin`, `vpn`, `staging`, `jira`, `git`, `jenkins` ;
- collecte partielle due a une source indisponible.

Ce score n'est pas une preuve de compromission. Il sert a prioriser les points d'attention visibles publiquement.

## Tests

```powershell
python -m unittest discover -s .\tests
```

Les tests couvrent :

- normalisation de domaine ;
- extraction de metadonnees PDF ;
- extraction de metadonnees Office Open XML ;
- scoring de risque ;
- comparaison de rapports.

## Docker

L'image utilise `python:3.12-slim`.

Build :

```powershell
docker build -t osint-harvester .
```

Run :

```powershell
docker run --rm -v ${PWD}\reports:/app/reports osint-harvester example.com --limit 50 --metadata-limit 0 --out /app/reports/example-docker
```



## Roadmap

- Ajouter une configuration YAML pour les seuils de scoring.
- Ajouter des cles API optionnelles pour SecurityTrails, Shodan ou Have I Been Pwned.
- Ajouter un export SARIF ou JUnit pour integration CI.
- Ajouter une interface web locale en lecture seule.
