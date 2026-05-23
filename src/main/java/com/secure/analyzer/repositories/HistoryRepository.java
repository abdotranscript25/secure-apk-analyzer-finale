package com.secure.analyzer.repositories;

import com.secure.analyzer.models.AnalysisHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface HistoryRepository extends JpaRepository<AnalysisHistory, Long> {

    Page<AnalysisHistory> findAllByOrderByAnalysisDateDesc(Pageable pageable);

    Page<AnalysisHistory> findByPackageNameContainingIgnoreCaseOrderByAnalysisDateDesc(
            String packageName, Pageable pageable);

    Page<AnalysisHistory> findByFileNameContainingIgnoreCaseOrderByAnalysisDateDesc(
            String fileName, Pageable pageable);

    Page<AnalysisHistory> findByRiskLevelOrderByAnalysisDateDesc(
            String riskLevel, Pageable pageable);

    @Query("SELECT AVG(a.securityScore) FROM AnalysisHistory a " +
            "WHERE a.analysisDate BETWEEN :startDate AND :endDate")
    Double getAverageScoreBetween(@Param("startDate") LocalDateTime startDate,
                                  @Param("endDate") LocalDateTime endDate);

    @Query("SELECT a.riskLevel, COUNT(a) FROM AnalysisHistory a " +
            "GROUP BY a.riskLevel")
    List<Object[]> getRiskLevelDistribution();

    List<AnalysisHistory> findByPackageNameOrderByAnalysisDateDesc(String packageName);

    @Query("SELECT FUNCTION('DATE', a.analysisDate), COUNT(a) FROM AnalysisHistory a " +
            "WHERE a.analysisDate >= :startDate " +
            "GROUP BY FUNCTION('DATE', a.analysisDate) " +
            "ORDER BY FUNCTION('DATE', a.analysisDate)")
    List<Object[]> countByDay(@Param("startDate") LocalDateTime startDate);

    // Méthode corrigée pour supprimer les analyses anciennes
    List<AnalysisHistory> findByAnalysisDateBefore(LocalDateTime date);

    void deleteByAnalysisDateBefore(LocalDateTime date);
}