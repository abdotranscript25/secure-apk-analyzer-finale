# 🔒 Secure APK Analyzer

<div align="center">

![Java](https://img.shields.io/badge/Java-17%2B-blue)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.1.5-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Android%20APK-orange)

**Analyse statique avancée d'applications Android | Scoring AHP | IA Comportementale | Historique | Comparaison**

[Installation](#-installation) • [Fonctionnalités](#-fonctionnalités) • [Utilisation](#-utilisation) • [Architecture](#-architecture) • [API](#-api-endpoints)

</div>

---

## 📋 Table des matières

1. [Aperçu](#-aperçu)
2. [Fonctionnalités](#-fonctionnalités)
3. [Architecture](#-architecture-du-projet)
4. [Installation](#-installation)
5. [Configuration](#-configuration)
6. [Utilisation](#-utilisation)
7. [Analyse des résultats](#-analyse-des-résultats)
8. [API Endpoints](#-api-endpoints)
9. [Base de données](#-base-de-données)
10. [Export des rapports](#-export-des-rapports)
11. [Comparaison d'analyses](#-comparaison-danalyses)
12. [Roadmap](#-roadmap)
13. [Technologies utilisées](#-technologies-utilisées)

---

## 🎯 Aperçu

**Secure APK Analyzer** est un outil d'analyse statique de fichiers APK Android, inspiré de **MobSF** (Mobile Security Framework). Il détecte automatiquement les vulnérabilités de sécurité, évalue le niveau de risque et génère des rapports détaillés.

### Pourquoi cet outil ?

| Problème | Solution |
|----------|----------|
| Les apps Android contiennent souvent des vulnérabilités critiques | Détection automatique de 20+ types de vulnérabilités |
| Les développeurs manquent de visibilité sur la sécurité de leur code | Scoring AHP (0-100) avec grade (A+ à F) |
| Difficile de suivre l'évolution entre deux versions | Historique complet et comparaison d'analyses |
| Les rapports de sécurité sont souvent trop techniques | Interface web claire avec recommandations exploitables |

---

## ✨ Fonctionnalités

### 🔍 Analyse statique complète

| Catégorie | Détections |
|-----------|------------|
| **AndroidManifest.xml** | `allowBackup`, `debuggable`, `usesCleartextTraffic`, composants exportés, SDK obsolète |
| **Permissions** | 23 permissions dangereuses (CAMERA, SMS, LOCALISATION, etc.) |
| **Code dangereux** | `Runtime.exec()`, `ProcessBuilder`, `DexClassLoader`, WebView JS, SQL injection |
| **Cryptographie** | MD5, SHA-1, DES, RC4, ECB, `Random()` au lieu de `SecureRandom` |
| **Secrets en dur** | API keys (Google, AWS, Stripe, Firebase), JWT, Bearer tokens, clés PEM |
| **Réseau** | URLs HTTP, IPs internes, `NetworkSecurityConfig` faibles |
| **Logs sensibles** | `Log.d/v/i/e` contenant password/token/secret |
| **Anti-debug** | Détection de code anti-debug |

### 📊 Scoring AHP (Analytic Hierarchy Process)

```
Score final = 100 - (pénalité_pondérée + pénalité_log + pénalité_critique)

Poids AHP :
  CRITICAL : 0.40
  HIGH     : 0.32
  MEDIUM   : 0.16
  LOW      : 0.12
```

**Grades de sécurité :**

| Grade | Score | Interprétation |
|-------|-------|----------------|
| **A+** | 90-100 | Excellent — Application très sécurisée |
| **A** | 80-89 | Bon — Quelques améliorations mineures |
| **B** | 70-79 | Correct — Des vulnérabilités à corriger |
| **C** | 60-69 | Passable — Plusieurs problèmes de sécurité |
| **D** | 50-59 | Faible — Risques significatifs |
| **E** | 40-49 | Mauvais — Nombreuses vulnérabilités |
| **F** | 0-39 | Critique — Application dangereuse |

### 🧠 IA Comportementale — `RiskPredictor`

| Verdict | Description |
|---------|-------------|
| **MALWARE** | Patterns malveillants détectés |
| **HIGH_RISK** | Risque élevé d'activités malveillantes |
| **SUSPICIOUS** | Comportements suspects |
| **SAFE** | Application sûre |

### 📁 Historique et Stockage

- **Base de données H2** — stockage de toutes les analyses
- **Rapports JSON** — données structurées exploitables par d'autres outils
- **Rapports PDF** — documents prêts à être partagés
- **Console H2** — interface SQL pour requêter l'historique (`/h2-console`)

### 🔄 Comparaison d'analyses

- Sélectionner deux analyses dans l'historique
- Visualisation côte à côte des scores et vulnérabilités
- Calcul automatique de l'évolution (amélioration / dégradation)
- Idéal pour suivre la sécurité entre deux versions

---

## 🏗️ Architecture du projet

```
┌─────────────────────────────────────────────────────────────────────┐
│                          APK Android                                │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      1. UltimateAnalyzer                            │
│  ├── Extraction ZIP                                                 │
│  ├── Décompilation JADX                                             │
│  ├── Analyse Manifest                                               │
│  ├── Analyse ressources                                             │
│  ├── Analyse code Java (20+ règles)                                 │
│  ├── Détection secrets                                              │
│  └── Extraction URLs / emails / IPs                                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                     2. AHPScorerAdapted                             │
│  ├── Filtrage faux positifs                                         │
│  ├── Calcul pénalité pondérée (AHP)                                 │
│  ├── Normalisation logarithmique                                    │
│  └── Score 0-100 + Grade + Risque                                   │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    3. Export et Stockage                            │
│  ├── Rapport JSON                                                   │
│  ├── Rapport PDF                                                    │
│  └── Base H2 (historique)                                           │
└──────────────────────────────┬──────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────────┐
│                     4. Interface Web                                │
│  ├── /          → Upload APK                                        │
│  ├── /report    → Résultats détaillés                               │
│  ├── /history   → Liste des analyses                                │
│  └── /compare   → Comparaison                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Structure des dossiers

```
secure-apk-analyzer/
├── src/main/java/com/secure/analyzer/
│   ├── controllers/
│   │   ├── APKAnalyzerController.java   # Analyse + export
│   │   └── HistoryController.java       # Pages d'historique
│   ├── models/
│   │   ├── SecurityFinding.java         # Modèle de vulnérabilité
│   │   └── AnalysisHistory.java         # Entité JPA
│   ├── repositories/
│   │   └── HistoryRepository.java       # Accès base H2
│   ├── services/
│   │   └── HistoryService.java          # Logique métier
│   ├── analyzers/
│   │   ├── UltimateAnalyzer.java        # Analyse statique principale
│   │   └── AHPScorerAdapted.java        # Scoring AHP
│   ├── classifiers/
│   │   └── RiskPredictor.java           # IA comportementale
│   ├── ai/
│   │   └── AIBehaviorAnalyzer.java      # Analyse comportementale
│   └── utils/
│       └── ReportExporter.java          # Export PDF/JSON
├── src/main/resources/
│   ├── application.properties           # Configuration
│   └── templates/                       # Pages Thymeleaf
│       ├── index.html
│       ├── report.html
│       ├── history.html
│       ├── history-detail.html
│       └── history-compare.html
├── tools/jadx/                          # Décompilateur JADX
└── pom.xml                              # Dépendances Maven
```

---

## 🚀 Installation

### Prérequis

| Logiciel | Version | Vérification |
|----------|---------|--------------|
| Java JDK | 17+ | `java -version` |
| Maven | 3.8+ | `mvn -version` |
| Git | 2.x | `git --version` |

### Cloner et lancer

```bash
# 1. Cloner le dépôt
git clone https://github.com/abdotranscript25/secure-apk-analyzer-finale.git
cd secure-apk-analyzer-finale

# 2. Compiler le projet
mvn clean compile

# 3. Lancer l'application
mvn spring-boot:run
```

### Accès à l'application

| Interface | URL |
|-----------|-----|
| Accueil | http://localhost:8080 |
| Console H2 | http://localhost:8080/h2-console |
| Historique | http://localhost:8080/history |
| API Stats | http://localhost:8080/history/api/stats |

---

## ⚙️ Configuration

### `application.properties`

```properties
# Spring Boot
spring.application.name=SecureAPK-Analyzer

# Base H2
spring.datasource.url=jdbc:h2:file:./data/secureapkdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=

# JPA
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false

# Console H2
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# Upload
spring.servlet.multipart.max-file-size=100MB
spring.servlet.multipart.max-request-size=100MB

# Serveur
server.port=8080
```

### Configuration JADX *(optionnelle)*

Par défaut, JADX est cherché dans `tools/jadx/bin/jadx.bat`. Pour modifier :

```properties
jadx.path=C:\\votre\\chemin\\jadx.bat
```

---

## 📖 Utilisation

### 1. Analyser une APK

1. Accédez à `http://localhost:8080`
2. Cliquez sur "Parcourir" et sélectionnez un fichier `.apk`
3. Cliquez sur "Analyser l'APK"
4. Attendez la fin de l'analyse (quelques secondes à minutes selon la taille)

### 2. Interpréter le rapport

Le rapport affiche : score global avec cercle coloré, grade (A+ à F), niveau de risque, compteurs par sévérité, détails par catégorie (Manifest, Code, Réseau, Crypto, Données) et plan de remédiation priorisé.

### 3. Comparer deux analyses

Dans la page d'historique, cochez deux analyses → une barre de comparaison apparaît → cliquez sur "Comparer" → visualisez l'évolution des scores.

### 4. Exporter les rapports

Depuis le rapport : boutons **📄 PDF** et **📋 JSON** dans la barre supérieure.
Depuis l'historique : boutons dans la colonne "Actions" de chaque analyse.

---

## 📊 Analyse des résultats

### Exemple de rapport

```
╔══════════════════════════════════════════════════════════╗
║              RÉSULTAT FINAL (AHP v2)                     ║
╠══════════════════════════════════════════════════════════╣
║  Package   : com.example.numberbook                      ║
║  Score AHP : 39/100  │  Grade : F  │  Confiance : 95%   ║
║  Risque    : CRITICAL                                    ║
╠══════════════════════════════════════════════════════════╣
║  🔴 CRITICAL : 8       🟠 HIGH : 3                       ║
║  🟡 MEDIUM  : 10       🟢 LOW  : 0                       ║
║  📊 Findings : 21 (dont 3 faux positifs filtrés)         ║
╚══════════════════════════════════════════════════════════╝
```

### Interprétation des sévérités

| Niveau | Action requise | Délai |
|--------|---------------|-------|
| 🔴 CRITICAL | Correction immédiate | Aujourd'hui |
| 🟠 HIGH | Correction prioritaire | 7 jours |
| 🟡 MEDIUM | Planifier la correction | Prochain sprint |
| 🟢 LOW | Surveillance seulement | Optionnel |

---

## 🔌 API Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/analyze` | Analyser une APK (`multipart/form-data`) |
| `GET` | `/history` | Page d'historique |
| `GET` | `/history/{id}` | Détail d'une analyse |
| `GET` | `/history/compare?id1=X&id2=Y` | Comparaison |
| `POST` | `/export/pdf` | Exporter le dernier rapport en PDF |
| `POST` | `/export/json` | Exporter le dernier rapport en JSON |
| `GET` | `/download/pdf/{id}` | Télécharger PDF d'une analyse |
| `GET` | `/download/json/{id}` | Télécharger JSON d'une analyse |
| `GET` | `/history/api/stats` | Statistiques JSON |

```bash
# Analyser une APK
curl -X POST -F "file=@app.apk" http://localhost:8080/analyze

# Obtenir les statistiques JSON
curl http://localhost:8080/history/api/stats
```

---

## 💾 Base de données

### Connexion à la console H2

```
Driver Class : org.h2.Driver
JDBC URL     : jdbc:h2:file:./data/secureapkdb
User Name    : sa
Password     : (laisser vide)
```

### Table principale — `ANALYSIS_HISTORY`

| Colonne | Type | Description |
|---------|------|-------------|
| `id` | BIGINT | Identifiant unique |
| `package_name` | VARCHAR | Nom du package |
| `security_score` | INT | Score 0-100 |
| `security_grade` | VARCHAR | Grade A+ à F |
| `risk_level` | VARCHAR | CRITICAL/HIGH/MEDIUM/LOW |
| `critical_count` | INT | Nombre de vulnérabilités critiques |
| `analysis_date` | TIMESTAMP | Date de l'analyse |
| `report_json_path` | VARCHAR | Chemin du fichier JSON |
| `report_pdf_path` | VARCHAR | Chemin du fichier PDF |

### Requêtes utiles

```sql
-- Dernières analyses
SELECT * FROM ANALYSIS_HISTORY ORDER BY ANALYSIS_DATE DESC LIMIT 10;

-- Analyses critiques
SELECT * FROM ANALYSIS_HISTORY WHERE RISK_LEVEL = 'CRITICAL';

-- Score moyen des 30 derniers jours
SELECT AVG(SECURITY_SCORE) FROM ANALYSIS_HISTORY
WHERE ANALYSIS_DATE > DATEADD('DAY', -30, NOW());

-- Distribution des risques
SELECT RISK_LEVEL, COUNT(*) FROM ANALYSIS_HISTORY GROUP BY RISK_LEVEL;
```

---

## 📄 Export des rapports

### Format JSON

```json
{
  "report_date": "2024-01-15 14:30:00",
  "package_name": "com.example.app",
  "security_score": 39,
  "security_grade": "F",
  "risk_level": "CRITICAL",
  "severity_counts": {
    "critical": 8,
    "high": 3,
    "medium": 10,
    "low": 0
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "type": "HARDCODED_SECRET",
      "location": "MainActivity.java",
      "evidence": "API_KEY = \"AIzaSyD-xxxxx\"",
      "recommendation": "Stocker les secrets dans un gestionnaire sécurisé"
    }
  ]
}
```

### Format PDF

Le PDF généré contient : score et grade avec cercle coloré, tableau récapitulatif des vulnérabilités, liste détaillée avec localisation, plan de remédiation par priorité.

---

## 🔄 Comparaison d'analyses

```
🔄 Comparaison d'analyses

Critère              │ v1.0 (25/100) │ v2.0 (39/100) │ Évolution
─────────────────────┼───────────────┼───────────────┼────────────
Score sécurité       │ 25/100 (F)    │ 39/100 (F)    │ ▲ +14 pts
🔴 Critiques         │ 9             │ 8             │ -1
🟠 Élevées           │ 4             │ 3             │ -1
🟡 Moyennes          │ 15            │ 10            │ -5

📊 Évolution globale : ✅ Amélioration de 14 points
```

---

## 🗺️ Roadmap

### ✅ Déjà implémenté

- [x] Analyse statique complète (Manifest, Code, Crypto, Réseau)
- [x] Scoring AHP avec pondération optimisée
- [x] IA comportementale (`RiskPredictor`)
- [x] Export PDF et JSON
- [x] Base H2 avec historique
- [x] Comparaison d'analyses
- [x] Interface web responsive

### 🔜 En développement

- [ ] **Guide IA post-analyse** : Recommandations de correction par LLM (Ollama)
- [ ] **Analyse multi-APK** : Upload par lot
- [ ] **Graphiques d'évolution** : Chart.js pour visualiser les tendances
- [ ] **Export ZIP** : Télécharger tous les rapports d'un package
- [ ] **API REST complète** : Endpoints pour intégration CI/CD

### 📅 Idées futures

- Plugins CI/CD (GitHub Actions, GitLab CI, Jenkins)
- Extension VS Code
- Mode SaaS avec authentification
- Rapports par email
- Intégration avec JIRA / Trello

---

## 🛠️ Technologies utilisées

### Backend

| Technologie | Version | Utilisation |
|-------------|---------|-------------|
| Spring Boot | 3.1.5 | Framework principal |
| Spring Data JPA | - | ORM pour base H2 |
| Thymeleaf | - | Templating HTML |
| H2 Database | - | Base de données intégrée |
| iText 7 | 7.2.5 | Génération PDF |
| Jackson | 2.15.2 | Manipulation JSON |
| JADX | - | Décompilation APK |

### Frontend

| Technologie | Utilisation |
|-------------|-------------|
| Bootstrap 5 | CSS Framework |
| Thymeleaf | Rendu dynamique |
| Chart.js | Graphiques *(optionnel)* |
| Font Awesome | Icônes |

---

## Démonstartion : 



https://github.com/user-attachments/assets/0c615675-30c0-4794-b986-a25329430c2d




## 📚 RÉCAPITULATIF – CE QUE NOUS AVONS CONSTRUIT

---

### ✅ Synthèse du projet

Ce projet va au-delà de la version précédente en ajoutant un **scoring AHP** (méthode multicritère pondérée), un **historique persistant** en base H2, une **comparaison d'analyses** entre versions, et un **export double format** (PDF + JSON) — le tout dans une interface web Spring Boot complète.

---

### 📝 Les points essentiels à retenir

| # | Point clé |
|---|-----------|
| 1 | **AHP** pondère les vulnérabilités : CRITICAL (×0.40) > HIGH (×0.32) > MEDIUM (×0.16) > LOW (×0.12) |
| 2 | **H2** est une base SQL intégrée — aucun serveur externe requis, fichier local `./data/secureapkdb` |
| 3 | **La comparaison** nécessite que les deux analyses aient un rapport JSON stocké |
| 4 | **iText 7** génère les PDF côté serveur sans dépendance navigateur |
| 5 | **JADX** est optionnel — l'analyse peut fonctionner en mode dégradé sans décompilation |
| 6 | Le **filtrage des faux positifs** est critique pour la précision du score AHP |

---

### 🎯 Compétences acquises

| Compétence | Niveau |
|------------|--------|
| Analyse statique d'APK (20+ règles) | ✅ Maîtrisé |
| Scoring multicritère AHP | ✅ Maîtrisé |
| Persistance avec Spring Data JPA + H2 | ✅ Maîtrisé |
| Export PDF avec iText 7 | ✅ Maîtrisé |
| Comparaison et suivi d'analyses | ✅ Maîtrisé |
| Interface web Spring Boot + Thymeleaf | ✅ Maîtrisé |

---

### 👥 Auteurs

| Membre | 
|--------|
| Ait Zidane Salma | 
| El Hachimi Abdelhamid |
| El Ouatik Mourad |


---

### 📅 Version

| Élément | Information |
|---------|-------------|
| **Date** | Mai 2026 |
| **Version** | 2.0 |
| **Statut** | ✅ Finalisé |
