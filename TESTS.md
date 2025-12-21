# Plan de tests - sec-ia

## Préparation
- activer l'env virtuel : `& .\.venv\Scripts\Activate.ps1`
- installer/valider les dépendances (déjà fait).
- ajouter `$env:SAVE_REPORTS="1"` et `$env:REPORTS_DIR="analyses"` pour avoir des rapports persistants.
- lancer l'ensemble avec :  
  `powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1`
- vérifier `http://localhost:8000` (API) et `http://localhost:8502` (Streamlit unifié).

## 1. Génération IA (+ analyse)
1. Onglet “Génération IA” : description “API REST with JWT”, langage `python`, provider `simulate`, scanners Bandit + Gemini.
2. Cliquer “Générer et Analyser”.
3. Vérifier : code affiché, métriques HIGH/MEDIUM/LOW/Risk, export JSON/PDF disponible, rapport `analyses/report_generation_*.json` créé.
4. Refaire cette même requête → message “Analyse déjà effectuée”, résultat chargé depuis l’historique (pas de nouveau scan).

## 2. Analyse de code
1. Coller un snippet Python vulnérable (SQLi/command injection) et cocher les scanners.
2. Lancer “Analyser (Complet)” → voir findings détaillés avec filtre par gravité/scanner.
3. Relancer identique → message “Analyse déjà effectuée”.
4. Lancer “Analyser (Rapide)” (même snippet) → vue compacte ; vérifier `analyses/report_snippet_fast_*.json`.

## 3. Analyse GitHub
1. URL : `https://github.com/OWASP/juice-shop/tree/main`.
2. Activer tous les scanners (Bandit, Semgrep, Snyk, Gemini).
3. Cliquer “Analyser” → observer barre de progression/status.
4. Vérifier que les findings remontent et apparaissent dans le rapport JSON/expander.
5. Relancer : message “Analyse déjà effectuée” + chargement instantané.

## 4. Comparaison Providers
1. Entrer une description (“User login system”) et langage `javascript`.
2. Cliquer “Comparer les Providers”.
3. S’assurer que chaque provider retourne un bloc généré avec tokens/cost/risk score.
4. Relancer même comparaison pour vérifier les rapports réutilisés.

## 5. Dashboard
1. Après une analyse, switcher sur “Dashboard”.
2. Vérifier que les métriques HIGH/MEDIUM/LOW/Risk reprennent la dernière analyse.
3. Voir le graphique de distribution (si matplotlib installé) sinon message d’info.

## 6. Historique
1. Ouvrir “Historique” : confirmer affichage hiérarchique Date > Type > Gravité.
2. Cliquer sur un rapport pour voir métadonnées, findings, génération (provider/model/tokens).
3. Cliquer sur “Télécharger JSON”.
4. Relancer une analyse listée → message “Analyse déjà effectuée. Rapport chargé depuis l’historique.”

## 7. API/endpoints
1. `/analyze` avec payload `{"language":"python","code":"print('a')","scanners":["bandit","gemini_detector"]}`.
2. `/analyze-fast` avec snippet python.
3. `/analyze-github` avec `{"url":"https://github.com/OWASP/juice-shop/tree/main"}`.
4. `/generate-and-analyze` avec description simple.
5. Chaque réponse doit contenir `metadata.request_hash` et générer un fichier dans `analyses/`.

## 8. Export
- Depuis chaque analyse, tester les boutons Download JSON et Generate PDF.
- Vérifier que les fichiers contiennent les mêmes données (metadonnées + findings).

## 9. Nettoyage
- Supprimer les rapports non voulus dans `analyses/`.
- Relancer `scripts/compile_all.ps1` après modifications si besoin.
