# Framework de Bonnes Pratiques : Adoption Sécurisée des Outils IA de Génération de Code

## 1. Introduction

### Risques spécifiques de l'IA générative

Les outils de génération de code par IA (GitHub Copilot, Amazon CodeWhisperer, Tabnine, etc.) 
présentent des risques de sécurité uniques :

- **Vulnérabilités probabilistes** : Le code généré reflète les patterns de l'entraînement, 
  incluant potentiellement du code vulnérable.
- **Secrets hardcodés** : Reproduction involontaire de clés API, tokens, mots de passe.
- **Injection de code malveillant** : Risque de "data poisoning" dans les corpus d'entraînement.
- **Non-conformité réglementaire** : Code non conforme RGPD, PCI-DSS, HIPAA.
- **Dépendances vulnérables** : Suggestions de packages obsolètes ou compromis.

### Statistiques du projet (à actualiser)

Basé sur l'analyse de **N** snippets générés par IA :

- **X%** contiennent au moins 1 vulnérabilité HIGH
- **Y%** exposent des secrets (patterns API key, tokens)
- **Z%** utilisent `eval()`, `exec()` ou équivalents dangereux
- **Temps moyen de détection** : T secondes (Bandit + Semgrep + detector)

---

## 2. Méthodologie d'Adoption Sécurisée

### Phase 1 : Audit Préliminaire (Semaine 1-2)

**Objectif** : Évaluer la maturité sécurité actuelle

1. **Inventaire des outils IA** déjà utilisés (IDE plugins, CLI, etc.)
2. **Audit du code existant** : lancer campagne de 100 générations simulées
3. **Configuration baseline** : définir seuils acceptables (ex: 0 HIGH, <5 MEDIUM)
4. **Formation équipe** : sensibilisation aux risques IA-générés

**Livrables** :
- ✅ Rapport d'audit initial
- ✅ Baseline de sécurité documentée

---

### Phase 2 : Configuration des Scanners (Semaine 3)

**Objectif** : Mettre en place la détection automatique

1. **Installation des scanners** :
   ```bash
   pip install bandit semgrep
   npm install -g snyk
   ```

2. **Configuration par langage** :
   - Python : Bandit + Semgrep (config p/python)
   - JavaScript : Semgrep + ESLint (plugin security)
   - Java : Semgrep + SpotBugs
   - C# : Semgrep + Roslyn Analyzers

3. **Tuning des règles** :
   - Désactiver faux positifs récurrents
   - Ajouter règles custom pour patterns métier

4. **Tests de validation** :
   ```bash
   python cli/security_tool.py generate -d "API login" -l python
   # Vérifier que les scanners détectent les vulnérabilités injectées
   ```

**Livrables** :
- ✅ Configuration scanner par langage
- ✅ Documentation de tuning

---

### Phase 3 : Intégration CI/CD (Semaine 4)

**Objectif** : Automatiser le scan à chaque commit

1. **GitHub Actions** (voir `.github/workflows/devsecops_scan.yml`) :
   ```yaml
   - name: Scan AI-generated code
     run: |
       python cli/security_tool.py analyse-repo . --extensions .py,.js
       if [ $HIGH_COUNT -gt 0 ]; then exit 1; fi
   ```

2. **Pre-commit hooks** :
   ```bash
   # .git/hooks/pre-commit
   #!/bin/bash
   python cli/security_tool.py analyse-fast changed_files.txt
   ```

3. **Pull Request gates** :
   - Bloquer merge si HIGH > 0
   - Require review si MEDIUM > 5

**Livrables** :
- ✅ Pipeline CI/CD configuré
- ✅ Pre-commit hooks actifs

---

### Phase 4 : Formation des Développeurs (Semaine 5-6)

**Objectif** : Sensibiliser et responsabiliser

1. **Workshop sécurité IA (2h)** :
   - Démonstration live : générer code vulnérable avec Copilot
   - Analyse en temps réel avec notre plateforme
   - Exercices pratiques de correction

2. **Documentation interne** :
   - Guide "Comment utiliser Copilot en sécurité"
   - Checklist avant commit
   - Catalogue de patterns dangereux

3. **Champions sécurité** :
   - Désigner 1 référent par équipe
   - Revue mensuelle des métriques

**Livrables** :
- ✅ Support de formation
- ✅ Documentation développeur

---

## 3. Checklist de Sécurité

### Avant chaque commit de code IA-généré

- [ ] **Scan multi-outils** : Min. 2 scanners (Bandit+Semgrep ou équivalent)
- [ ] **Zéro HIGH** : Aucune vulnérabilité critique non résolue
- [ ] **Review secrets** : Vérification manuelle des API keys, tokens, passwords
- [ ] **Tests injection** : Si code manipule input utilisateur, tester SQL injection, XSS
- [ ] **Validation dépendances** : `pip-audit` / `npm audit` pour détecter CVE
- [ ] **Revue logique** : Comprendre le code généré (pas de copier-coller aveugle)
- [ ] **Tests unitaires** : Couvrir au moins les cas critiques

### Revue manuelle obligatoire si

✋ HIGH severity détectée  
✋ Code manipule données sensibles (PII, finance, santé)  
✋ Code fait des appels réseau (HTTP, DB, API externes)  
✋ Code utilise eval/exec ou équivalents  
✋ Code génère du SQL/HTML dynamique

---

## 4. Patterns de Défaillance Courants

### 4.1 Secrets Hardcodés

**Prévalence** : X% des générations (à actualiser avec vraies stats)

**Exemples détectés** :
```python
# ❌ DANGEREUX
API_KEY = "sk-1234567890abcdef"
conn = pymongo.MongoClient("mongodb://admin:password123@prod-db")
```

**Remédiation** :
```python
# ✅ SÉCURISÉ
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable required")
```

**Règles de détection** :
- Bandit: B105 (hardcoded password)
- Semgrep: `generic.secrets.security`
- Detector custom: regex AWS keys, Stripe, SendGrid

---

### 4.2 Injection SQL

**Prévalence** : Y% des générations (à actualiser)

**Exemples** :
```python
# ❌ DANGEREUX
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

**Remédiation** :
```python
# ✅ SÉCURISÉ (requête paramétrée)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

---

### 4.3 Exécution Dynamique

**Prévalence** : Z%

**Exemples** :
```python
# ❌ DANGEREUX
user_code = request.form['code']
exec(user_code)
```

**Remédiation** :
- Interdire `eval()`, `exec()`, `compile()` sauf cas justifié
- Utiliser `ast.literal_eval()` pour parser données safe
- Sandbox si exécution nécessaire (Docker, VM isolée)

---

## 5. Recommandations par Langage

### Python

- **Scanners** : Bandit (obligatoire) + Semgrep
- **Seuils** : 0 HIGH, <3 MEDIUM
- **Focus** : pickle (désérialisation), eval/exec, subprocess shell=True
- **Best practices** : Type hints (mypy), f-strings (pas %), requests avec timeout

### JavaScript/TypeScript

- **Scanners** : Semgrep + ESLint (plugin security)
- **Seuils** : 0 HIGH, <5 MEDIUM
- **Focus** : eval(), innerHTML, XSS, prototype pollution
- **Best practices** : Content-Security-Policy, DOMPurify pour sanitization

### Java

- **Scanners** : Semgrep + SpotBugs
- **Seuils** : 0 HIGH, <3 MEDIUM
- **Focus** : Désérialisation, injection SQL (JDBC), XXE
- **Best practices** : PreparedStatement, input validation (Bean Validation)

---

## 6. Métriques de Succès

### Seuils acceptables (à ajuster par organisation)

| Sévérité | Seuil max | Action si dépassé |
|----------|-----------|-------------------|
| HIGH     | 0         | Blocage merge automatique |
| MEDIUM   | 5         | Review obligatoire |
| LOW      | 20        | Warning, merge autorisé |

### KPIs à suivre

- **Temps moyen de détection** : <10s par scan
- **Taux de faux positifs** : <10%
- **Taux de correction** : >95% des HIGH résolues en <24h
- **Couverture code** : 100% du code IA-généré scanné

### Reporting mensuel

- Dashboard avec évolution HIGH/MEDIUM/LOW
- Top 10 des vulnérabilités récurrentes
- Comparaison par provider IA (si plusieurs utilisés)
- Coût IA vs coût sécurité (temps dev passé à corriger)

---

## 7. Ressources Complémentaires

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [Snyk Vulnerability Database](https://security.snyk.io/)
- Documentation de ce projet : `README.md`, `analyse_bandit.ipynb`

---

## Changelog

- **v1.0 (2024-XX-XX)** : Version initiale du framework
- **v1.1 (TBD)** : Intégration statistiques réelles campagne 100 prompts

---

**Auteur** : Projet PFA - Analyse Sécurité Code IA  
**Licence** : MIT  
**Contact** : [votre-email@example.com]

