package com.secure.analyzer.analyzers;

import com.secure.analyzer.models.SecurityFinding;
import java.util.*;
import java.util.regex.Pattern;

/**
 * DefaultApkWhitelist - Liste des éléments à ignorer car présents par défaut
 * dans toute APK ou générés automatiquement.
 *
 * Cela permet de réduire les faux positifs en ignorant :
 * - Les fichiers générés (R.java, BuildConfig.java, etc.)
 * - Les patterns de documentation (schemas.android.com, etc.)
 * - Les bibliothèques standard (androidx, kotlin, java, etc.)
 */
public class DefaultApkWhitelist {

    // Patterns à ignorer dans le contenu
    private static final List<Pattern> IGNORED_CONTENT_PATTERNS = Arrays.asList(
            Pattern.compile("schemas\\.android\\.com/apk/res/android"),
            Pattern.compile("www\\.w3\\.org"),
            Pattern.compile("http://schemas\\.android\\.com"),
            Pattern.compile("android\\.app\\.[\\w]+"),
            Pattern.compile("android\\.content\\.[\\w]+"),
            Pattern.compile("android\\.os\\.[\\w]+"),
            Pattern.compile("android\\.net\\.[\\w]+"),
            Pattern.compile("android\\.util\\.[\\w]+"),
            Pattern.compile("android\\.graphics\\.[\\w]+"),
            Pattern.compile("android\\.view\\.[\\w]+"),
            Pattern.compile("android\\.widget\\.[\\w]+"),
            Pattern.compile("androidx\\.[\\w\\.]+"),
            Pattern.compile("kotlin\\.[\\w\\.]+"),
            Pattern.compile("kotlinx\\.[\\w\\.]+"),
            Pattern.compile("java\\.[\\w\\.]+"),
            Pattern.compile("javax\\.[\\w\\.]+"),
            Pattern.compile("org\\.apache\\.[\\w\\.]+"),
            Pattern.compile("com\\.google\\.[\\w\\.]+"),
            Pattern.compile("com\\.facebook\\.[\\w\\.]+")
    );

    // Fichiers à ignorer complètement (générés automatiquement)
    private static final List<String> IGNORED_FILES = Arrays.asList(
            "R.java",
            "BuildConfig.java",
            "Manifest.java",
            "BR.java",
            "DataBindingComponent.java",
            "DataBinderMapperImpl.java",
            "ViewDataBinding.java",
            "ActivityBinding.java",
            "FragmentBinding.java"
    );

    // Extensions de fichiers à ignorer
    private static final List<String> IGNORED_EXTENSIONS = Arrays.asList(
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico",
            ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".m4a",
            ".dex", ".so", ".dll", ".aar", ".jar", ".class",
            ".ttf", ".otf", ".woff", ".woff2", ".eot",
            ".json", ".xml", ".html", ".htm", ".css", ".js", ".min.js"
    );

    // Patterns d'URL à ignorer (exemples, documentation, localhost)
    private static final List<Pattern> IGNORED_URL_PATTERNS = Arrays.asList(
            Pattern.compile("example\\.com", Pattern.CASE_INSENSITIVE),
            Pattern.compile("test\\.com", Pattern.CASE_INSENSITIVE),
            Pattern.compile("localhost", Pattern.CASE_INSENSITIVE),
            Pattern.compile("127\\.0\\.0\\.1"),
            Pattern.compile("schemas\\.android\\.com", Pattern.CASE_INSENSITIVE),
            Pattern.compile("w3\\.org", Pattern.CASE_INSENSITIVE),
            Pattern.compile("apache\\.org", Pattern.CASE_INSENSITIVE)
    );

    /**
     * Vérifie si un fichier doit être ignoré (fichier généré ou binaire)
     */
    public static boolean shouldIgnoreFile(String fileName) {
        if (fileName == null) return true;
        String lower = fileName.toLowerCase();

        for (String ignored : IGNORED_FILES) {
            if (lower.equals(ignored.toLowerCase()) || lower.endsWith("/" + ignored.toLowerCase())) {
                return true;
            }
        }

        for (String ext : IGNORED_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Vérifie si un contenu doit être ignoré (contenu générique)
     */
    public static boolean shouldIgnoreContent(String content, String fileName) {
        if (content == null) return true;

        String trimmed = content.trim();

        // Contenu trop court
        if (trimmed.length() < 10) return true;

        // Contenu qui n'est que des caractères spéciaux ou du whitespace
        if (trimmed.matches("[\\s\\W]+")) return true;

        // Vérifier les patterns ignorés
        for (Pattern pattern : IGNORED_CONTENT_PATTERNS) {
            if (pattern.matcher(content).find()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Vérifie si un finding doit être ignoré
     */
    public static boolean shouldIgnoreFinding(SecurityFinding finding) {
        if (finding == null) return true;

        // Ignorer les findings dans les commentaires
        String evidence = finding.getEvidence() != null ? finding.getEvidence() : "";
        if (CommentFilter.isCommentLine(evidence)) {
            return true;
        }

        // Ignorer les URLs de documentation ou exemples
        String lowerEvidence = evidence.toLowerCase();
        for (Pattern pattern : IGNORED_URL_PATTERNS) {
            if (pattern.matcher(lowerEvidence).find()) {
                return true;
            }
        }

        // Ignorer les emails d'exemple
        if (lowerEvidence.contains("@example.com") ||
                lowerEvidence.contains("@test.com") ||
                lowerEvidence.contains("test@")) {
            return true;
        }

        return false;
    }

    /**
     * Vérifie si une URL doit être ignorée
     */
    public static boolean shouldIgnoreUrl(String url) {
        if (url == null) return true;
        String lower = url.toLowerCase();

        for (Pattern pattern : IGNORED_URL_PATTERNS) {
            if (pattern.matcher(lower).find()) {
                return true;
            }
        }

        return false;
    }
}