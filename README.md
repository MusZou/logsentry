# LogSentry — Analyseur de logs SSH avec mapping MITRE ATT&CK

Script Python qui parse un fichier `auth.log` (format syslog standard),
détecte des patterns d'attaque courants et mappe chaque détection à une
technique du framework **MITRE ATT&CK**.

Aucune dépendance externe (bibliothèque standard uniquement).

## Détections implémentées

| Pattern | Technique MITRE | Sévérité |
|---|---|---|
| Rafale de tentatives échouées depuis une même IP | T1110.001 — Brute Force: Password Guessing | High |
| Nombreux noms d'utilisateur distincts testés depuis une même IP | T1087.001 — Account Discovery: Local Account | Medium |
| Connexion réussie après une rafale d'échecs (même IP) | T1078 — Valid Accounts | Critical |

## Utilisation

```bash
# Sur le fichier d'exemple fourni
python3 log_analyzer.py sample_logs/auth.log.sample

# Sur un vrai fichier auth.log (Linux)
python3 log_analyzer.py /var/log/auth.log

# Avec export JSON et seuils personnalisés
python3 log_analyzer.py /var/log/auth.log -o rapport.json --brute-threshold 8 --window 10
```

### Options

| Option | Description | Défaut |
|---|---|---|
| `logfile` | Fichier auth.log à analyser | requis |
| `--year` | Année pour interpréter les timestamps (les logs syslog n'ont pas d'année) | année courante |
| `--brute-threshold` | Nb de tentatives échouées déclenchant une alerte brute-force | 5 |
| `--enum-threshold` | Nb de comptes distincts testés déclenchant une alerte d'énumération | 5 |
| `--window` | Fenêtre glissante (minutes) pour la détection de brute-force | 5 |
| `-o, --output` | Export du rapport complet en JSON | aucun |

## Exemple de sortie

```
LogSentry — 23 événement(s) analysé(s), 4 adresse(s) IP source(s)

[CRITICAL]   T1078 — Valid Accounts
             IP source : 203.0.113.45
             Connexion réussie ('root') depuis 203.0.113.45 après 10 échec(s) — compte potentiellement compromis.

[HIGH]       T1110.001 — Brute Force: Password Guessing
             IP source : 203.0.113.45
             10 tentatives de connexion échouées depuis 203.0.113.45 en moins de 5 min.

Résumé : 4 constat(s) — 1 critical, 2 high, 1 medium
```

## Comment ça marche

1. Parsing ligne par ligne du fichier auth.log via regex (format syslog
   `sshd[PID]: ...` standard sur Debian/Ubuntu)
2. Regroupement des événements (échecs, succès) par adresse IP source
3. Application de 3 règles de détection basées sur des fenêtres
   temporelles et des seuils configurables
4. Chaque détection est directement mappée à une technique MITRE
   ATT&CK, avec sévérité et description

Le fichier `sample_logs/auth.log.sample` contient 3 scénarios simulés :
un brute-force réussi (compromission), une énumération de comptes, et
des connexions légitimes qui ne déclenchent aucune alerte — pratique
pour vérifier qu'il n'y a pas de faux positif.

## Limites connues (assumées, à mentionner en entretien)

- Détection par seuils fixes, pas de scoring statistique ou de machine
  learning — volontairement simple et explicable
- Ne couvre que l'authentification SSH (pas de logs web, pare-feu, etc.)
- Pas de résolution géographique des IP ni de liste de réputation/threat
  intel — purement basé sur le comportement observé dans les logs

## Pistes d'amélioration possibles

- Support d'autres formats de logs (Apache/Nginx, Windows Event Log)
- Enrichissement GeoIP et croisement avec des listes de réputation IP
- Détection de password spraying (peu de mots de passe, beaucoup de comptes)
- Export vers un format SIEM (CEF, Sigma rules)

## Auteur

Mustapha Zouaoui — projet réalisé dans le cadre d'une recherche
d'alternance en cybersécurité.
