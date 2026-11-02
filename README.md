# ssh-log-analyzer

Analyseur de journaux SSH (`auth.log`) en Python, qui repère les **tentatives de brute force** et les **connexions réussies suspectes**. Outil défensif (*blue team*) : il lit un fichier existant, il n'envoie rien sur le réseau.

## Ce qu'il détecte

- **Brute force** : une même IP qui échoue au moins *N* fois (5 par défaut) dans une fenêtre glissante (60 s par défaut).
- **Alerte critique** : une connexion **réussie** juste après une rafale d'échecs de la même IP, signe possible de compromission.
- Les IP les plus actives et les comptes les plus ciblés.

## Utilisation

```bash
python3 analyzer.py sample_auth.log --year 2026
```

```
Événements SSH analysés : 29
Échecs de connexion     : 26

IP les plus actives (échecs) :
  203.0.113.45     14
  198.51.100.23    7
  203.0.113.99     3
  192.0.2.25       2

ALERTE brute force (≥ 5 échecs en 60 s) :
  203.0.113.45     14 échecs dans la fenêtre
  198.51.100.23    7 échecs dans la fenêtre

ALERTE CRITIQUE (connexion réussie après une rafale d'échecs) :
  2026-10-12 14:40:38  198.51.100.23 a réussi à se connecter en tant que 'deploy' après 7 échecs
```

Options : `--threshold`, `--window` (secondes), `--year` (le format syslog n'indique pas l'année), `--json`.

`sample_auth.log` est un journal **entièrement fictif** : les adresses IP sont celles réservées à la documentation (RFC 5737). Il contient volontairement des cas normaux (fautes de frappe d'un utilisateur, échecs étalés sur la journée) pour vérifier qu'ils ne déclenchent pas d'alerte.

## Concepts illustrés

- Expressions régulières pour analyser des journaux.
- Fenêtre glissante (algorithme à deux pointeurs) pour détecter une rafale d'événements.
- Faux positifs : le seuil et la fenêtre sont réglables.
- Corrélation d'événements (échecs puis succès).

## Tests

```bash
python3 -m unittest -v
```

## Limites

- Format OpenSSH/syslog classique uniquement (pas `journald` directement).
- Une attaque lente, étalée sur des heures, passe sous le seuil.
- Ne bloque rien : il alerte seulement.

## Pistes d'amélioration

- Détecter le *password spraying* (une IP qui teste beaucoup de comptes différents).
- Exporter en CSV, générer une liste d'IP à bloquer pour un pare-feu.
- Gérer l'année automatiquement et la rotation des journaux.

## Licence

MIT, voir [LICENSE](LICENSE).

---

*Réalisé avec l'aide de Claude (IA), relu et testé par l'auteur.*
