package com.secure.analyzer.services;

import com.secure.analyzer.analyzers.UltimateAnalyzer;
import com.secure.analyzer.classifiers.RiskPredictor;
import com.secure.analyzer.models.AnalysisHistory;
import com.secure.analyzer.repositories.HistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class HistoryService {

    @Autowired
    private HistoryRepository historyRepository;

    /**
     * Sauvegarde une analyse dans l'historique
     */
    @Transactional
    public AnalysisHistory saveAnalysis(
            UltimateAnalyzer.UltimateReport report,
            RiskPredictor.PredictionResult prediction,
            String jsonPath,
            String pdfPath,
            long durationMs) {

        AnalysisHistory history = new AnalysisHistory();

        // Informations APK
        history.setFileName(report.fileName);
        history.setPackageName(report.packageName != null ? report.packageName : "Inconnu");
        history.setVersionName(report.versionName);
        history.setVersionCode(report.versionCode);
        history.setFileSizeMb(report.fileSize / 1024.0 / 1024.0);
        history.setMinSdk(report.minSdk);
        history.setTargetSdk(report.targetSdk);
        history.setTotalClasses(report.totalClasses);

        // Scores
        history.setSecurityScore(report.securityScore);
        history.setSecurityGrade(report.securityGrade);
        history.setRiskLevel(report.riskLevel);

        // Compteurs
        history.setCriticalCount(report.criticalCount);
        history.setHighCount(report.highCount);
        history.setMediumCount(report.mediumCount);
        history.setLowCount(report.lowCount);
        history.setTotalFindings(report.totalFindings);

        // Prédiction IA
        history.setPredictedRisk(prediction.riskCategory);
        history.setPredictionConfidence(prediction.confidenceScore);

        // Chemins des fichiers
        history.setReportJsonPath(jsonPath);
        history.setReportPdfPath(pdfPath);

        // Métadonnées
        history.setAnalysisDate(LocalDateTime.now());
        history.setAnalysisDurationMs(durationMs);

        return historyRepository.save(history);
    }

    /**
     * Récupère l'historique paginé
     */
    public Page<AnalysisHistory> getHistory(int page, int size, String search, String riskFilter) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("analysisDate").descending());

        if (search != null && !search.isEmpty()) {
            return historyRepository.findByPackageNameContainingIgnoreCaseOrderByAnalysisDateDesc(
                    search, pageable);
        }

        if (riskFilter != null && !riskFilter.isEmpty() && !riskFilter.equals("ALL")) {
            return historyRepository.findByRiskLevelOrderByAnalysisDateDesc(riskFilter, pageable);
        }

        return historyRepository.findAllByOrderByAnalysisDateDesc(pageable);
    }

    /**
     * Récupère une analyse par son ID
     */
    public AnalysisHistory getAnalysisById(Long id) {
        return historyRepository.findById(id).orElse(null);
    }

    /**
     * Supprime une analyse
     */
    @Transactional
    public boolean deleteAnalysis(Long id) {
        if (historyRepository.existsById(id)) {
            historyRepository.deleteById(id);
            return true;
        }
        return false;
    }

    /**
     * Statistiques globales pour le tableau de bord
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        // Nombre total d'analyses
        long totalAnalyses = historyRepository.count();
        stats.put("totalAnalyses", totalAnalyses);

        // Score moyen
        Double avgScore = historyRepository.getAverageScoreBetween(
                LocalDateTime.now().minusDays(30), LocalDateTime.now());
        stats.put("averageScore30Days", avgScore != null ? Math.round(avgScore * 10) / 10.0 : 0);

        // Distribution des risques
        List<Object[]> riskDistribution = historyRepository.getRiskLevelDistribution();
        Map<String, Long> riskMap = new HashMap<>();
        for (Object[] row : riskDistribution) {
            riskMap.put((String) row[0], (Long) row[1]);
        }
        stats.put("riskDistribution", riskMap);

        // Dernière analyse
        Page<AnalysisHistory> lastPage = historyRepository.findAllByOrderByAnalysisDateDesc(PageRequest.of(0, 1));
        if (lastPage.hasContent()) {
            stats.put("lastAnalysis", lastPage.getContent().get(0));
        }

        return stats;
    }

    /**
     * Compare deux analyses
     */
    public Map<String, Object> compareAnalyses(Long id1, Long id2) {
        AnalysisHistory a1 = getAnalysisById(id1);
        AnalysisHistory a2 = getAnalysisById(id2);

        Map<String, Object> comparison = new HashMap<>();
        comparison.put("analysis1", a1);
        comparison.put("analysis2", a2);

        // Différence de score
        int scoreDiff = a2.getSecurityScore() - a1.getSecurityScore();
        comparison.put("scoreDifference", scoreDiff);
        comparison.put("scoreTrend", scoreDiff > 0 ? "UP" : (scoreDiff < 0 ? "DOWN" : "STABLE"));

        // Différence de vulnérabilités
        comparison.put("criticalDiff", a2.getCriticalCount() - a1.getCriticalCount());
        comparison.put("highDiff", a2.getHighCount() - a1.getHighCount());
        comparison.put("mediumDiff", a2.getMediumCount() - a1.getMediumCount());
        comparison.put("lowDiff", a2.getLowCount() - a1.getLowCount());

        return comparison;
    }

    /**
     * Nettoie les anciennes analyses (plus de X jours)
     */
    @Transactional
    public int cleanupOldAnalyses(int days) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(days);
        List<AnalysisHistory> oldAnalyses = historyRepository.findByAnalysisDateBefore(cutoffDate);
        int count = oldAnalyses.size();
        historyRepository.deleteAll(oldAnalyses);
        return count;
    }
}