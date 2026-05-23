package com.secure.analyzer.analyzers;

import com.secure.analyzer.models.SecurityFinding;
import java.util.*;

/**
 * ScoreCalculator - Calcule le score de sécurité avec des pénalités équilibrées
 *
 * Améliorations par rapport à l'ancien système :
 * - Pénalités réduites (plus de 0 systématique)
 * - Plafonds par type (un type ne peut pas dominer)
 * - Normalisation pour les APK avec beaucoup de findings
 * - Bonus pour les applications bien sécurisées
 */
public class ScoreCalculator {

    // Pénalités de base (réduites par rapport à l'ancien 15/8/3/1)
    private static final double PENALTY_CRITICAL = 5.0;
    private static final double PENALTY_HIGH = 2.5;
    private static final double PENALTY_MEDIUM = 1.0;
    private static final double PENALTY_LOW = 0.3;

    // Plafonds pour éviter qu'un type de finding ne domine trop le score
    private static final double MAX_CRITICAL_PENALTY = 30.0;
    private static final double MAX_HIGH_PENALTY = 20.0;
    private static final double MAX_MEDIUM_PENALTY = 15.0;
    private static final double MAX_LOW_PENALTY = 5.0;

    /**
     * Calcule le score à partir du rapport
     */
    public static int calculateScore(UltimateAnalyzer.UltimateReport report) {
        if (report == null) return 100;

        // Appliquer les filtres sur les findings
        List<SecurityFinding> validFindings = filterFindings(report.getAllFindings());

        // Compter par sévérité
        int criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;

        for (SecurityFinding f : validFindings) {
            switch (f.getSeverity()) {
                case CRITICAL: criticalCount++; break;
                case HIGH: highCount++; break;
                case MEDIUM: mediumCount++; break;
                default: lowCount++; break;
            }
        }

        // Mettre à jour le rapport
        report.criticalCount = criticalCount;
        report.highCount = highCount;
        report.mediumCount = mediumCount;
        report.lowCount = lowCount;
        report.totalFindings = validFindings.size();

        // Calcul des pénalités avec plafonds
        double totalPenalty = 0;
        totalPenalty += Math.min(MAX_CRITICAL_PENALTY, criticalCount * PENALTY_CRITICAL);
        totalPenalty += Math.min(MAX_HIGH_PENALTY, highCount * PENALTY_HIGH);
        totalPenalty += Math.min(MAX_MEDIUM_PENALTY, mediumCount * PENALTY_MEDIUM);
        totalPenalty += Math.min(MAX_LOW_PENALTY, lowCount * PENALTY_LOW);

        // Facteur de normalisation : les APK avec beaucoup de findings sont moins pénalisées
        // car une partie sont des faux positifs
        double normalizationFactor = 1.0;
        if (validFindings.size() > 40) {
            normalizationFactor = 0.6;
        } else if (validFindings.size() > 25) {
            normalizationFactor = 0.75;
        } else if (validFindings.size() > 15) {
            normalizationFactor = 0.85;
        }
        totalPenalty *= normalizationFactor;

        // Calcul du score final
        int score = (int) Math.max(0, Math.min(100, 100 - totalPenalty));

        // Bonus pour APK bien sécurisées (peu de vrais problèmes)
        if (criticalCount == 0 && highCount == 0 && mediumCount <= 2) {
            score = Math.min(100, score + 15);
        } else if (criticalCount == 0 && highCount == 0 && mediumCount <= 5) {
            score = Math.min(100, score + 5);
        }

        // Arrondi à l'entier le plus proche
        return score;
    }

    /**
     * Filtre les findings (ignore les faux positifs)
     */
    private static List<SecurityFinding> filterFindings(List<SecurityFinding> findings) {
        List<SecurityFinding> filtered = new ArrayList<>();

        for (SecurityFinding f : findings) {
            if (!DefaultApkWhitelist.shouldIgnoreFinding(f)) {
                filtered.add(f);
            }
        }

        return filtered;
    }

    /**
     * Calcule le niveau de risque basé sur les compteurs
     */
    public static String calculateRiskLevel(int criticalCount, int highCount, int mediumCount) {
        if (criticalCount >= 2) return "CRITICAL";
        if (criticalCount >= 1) return "CRITICAL";
        if (highCount >= 4) return "HIGH";
        if (highCount >= 2) return "HIGH";
        if (highCount >= 1) return "MEDIUM";
        if (mediumCount >= 5) return "MEDIUM";
        if (mediumCount >= 1) return "LOW";
        return "VERY_LOW";
    }

    /**
     * Calcule le grade (A+ à F)
     */
    public static String calculateGrade(int score) {
        if (score >= 90) return "A+";
        if (score >= 80) return "A";
        if (score >= 70) return "B";
        if (score >= 60) return "C";
        if (score >= 50) return "D";
        if (score >= 35) return "E";
        return "F";
    }
}