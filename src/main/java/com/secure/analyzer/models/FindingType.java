package com.secure.analyzer.models;

/**
 * Types de vulnérabilités / findings — v3.0
 * avec mapping OWASP MASVS
 */
public enum FindingType {

    // Manifest
    BACKUP_CONFIGURATION    (MasvsCategory.MASVS_RESILIENCE),
    DEBUGGABLE              (MasvsCategory.MASVS_RESILIENCE),
    CLEARTEXT_TRAFFIC       (MasvsCategory.MASVS_NETWORK),
    OUTDATED_SDK            (MasvsCategory.MASVS_CODE),
    EXPORTED_COMPONENT      (MasvsCategory.MASVS_PLATFORM),
    TASK_AFFINITY           (MasvsCategory.MASVS_PLATFORM),
    NETWORK_SECURITY        (MasvsCategory.MASVS_NETWORK),

    // Permissions
    DANGEROUS_PERMISSION    (MasvsCategory.MASVS_PRIVACY),

    // Code
    DANGEROUS_CODE          (MasvsCategory.MASVS_CODE),
    SQL_INJECTION           (MasvsCategory.MASVS_CODE),
    WEBVIEW_VULNERABILITY   (MasvsCategory.MASVS_PLATFORM),
    SENSITIVE_LOG           (MasvsCategory.MASVS_CODE),
    HARDCODED_SECRET        (MasvsCategory.MASVS_AUTH),
    INSECURE_RANDOM         (MasvsCategory.MASVS_CRYPTO),

    // Crypto
    WEAK_CRYPTOGRAPHY       (MasvsCategory.MASVS_CRYPTO),
    INSECURE_CIPHER_MODE    (MasvsCategory.MASVS_CRYPTO),

    // Réseau
    INSECURE_CONNECTION     (MasvsCategory.MASVS_NETWORK),
    SSL_BYPASS              (MasvsCategory.MASVS_NETWORK),

    // Données
    INFORMATION_DISCLOSURE  (MasvsCategory.MASVS_STORAGE),
    INTERNAL_FILE           (MasvsCategory.MASVS_STORAGE),
    LOG_FILE                (MasvsCategory.MASVS_STORAGE);

    // ── Champ MASVS ───────────────────────────────────────────────────────────

    private final MasvsCategory masvsCategory;

    FindingType(MasvsCategory masvsCategory) {
        this.masvsCategory = masvsCategory;
    }

    public MasvsCategory getMasvsCategory() {
        return masvsCategory;
    }

    // ── Enum imbriquée MASVS ──────────────────────────────────────────────────

    public enum MasvsCategory {

        MASVS_STORAGE    ("MASVS-STORAGE",    "Stockage des données"),
        MASVS_CRYPTO     ("MASVS-CRYPTO",     "Cryptographie"),
        MASVS_AUTH       ("MASVS-AUTH",       "Authentification"),
        MASVS_NETWORK    ("MASVS-NETWORK",    "Communications réseau"),
        MASVS_PLATFORM   ("MASVS-PLATFORM",   "Interactions plateforme"),
        MASVS_CODE       ("MASVS-CODE",       "Qualité du code"),
        MASVS_RESILIENCE ("MASVS-RESILIENCE", "Résistance aux attaques"),
        MASVS_PRIVACY    ("MASVS-PRIVACY",    "Confidentialité");

        private final String code;
        private final String description;

        MasvsCategory(String code, String description) {
            this.code = code;
            this.description = description;
        }

        public String getCode()        { return code; }
        public String getDescription() { return description; }

        @Override
        public String toString()       { return code; }
    }
}