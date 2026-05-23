package com.secure.analyzer.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Entity
@Table(name = "analysis_history", indexes = {
        @Index(name = "idx_package_name", columnList = "packageName"),
        @Index(name = "idx_analysis_date", columnList = "analysisDate"),
        @Index(name = "idx_security_score", columnList = "securityScore")
})
public class AnalysisHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String fileName;

    @Column(nullable = false)
    private String packageName;

    private String versionName;

    private Integer versionCode;

    private Double fileSizeMb;

    private Integer minSdk;

    private Integer targetSdk;

    private Integer totalClasses;

    @Column(nullable = false)
    private Integer securityScore;

    @Column(nullable = false)
    private String securityGrade;

    @Column(nullable = false)
    private String riskLevel;

    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Integer totalFindings;

    private String predictedRisk;
    private Double predictionConfidence;

    private String reportJsonPath;
    private String reportPdfPath;

    @Column(nullable = false)
    private LocalDateTime analysisDate;

    private Long analysisDurationMs;

    // Constructeur par défaut (obligatoire pour JPA)
    public AnalysisHistory() {
        this.analysisDate = LocalDateTime.now();
    }

    // Getters et Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getVersionName() { return versionName; }
    public void setVersionName(String versionName) { this.versionName = versionName; }

    public Integer getVersionCode() { return versionCode; }
    public void setVersionCode(Integer versionCode) { this.versionCode = versionCode; }

    public Double getFileSizeMb() { return fileSizeMb; }
    public void setFileSizeMb(Double fileSizeMb) { this.fileSizeMb = fileSizeMb; }

    public Integer getMinSdk() { return minSdk; }
    public void setMinSdk(Integer minSdk) { this.minSdk = minSdk; }

    public Integer getTargetSdk() { return targetSdk; }
    public void setTargetSdk(Integer targetSdk) { this.targetSdk = targetSdk; }

    public Integer getTotalClasses() { return totalClasses; }
    public void setTotalClasses(Integer totalClasses) { this.totalClasses = totalClasses; }

    public Integer getSecurityScore() { return securityScore; }
    public void setSecurityScore(Integer securityScore) { this.securityScore = securityScore; }

    public String getSecurityGrade() { return securityGrade; }
    public void setSecurityGrade(String securityGrade) { this.securityGrade = securityGrade; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public Integer getCriticalCount() { return criticalCount; }
    public void setCriticalCount(Integer criticalCount) { this.criticalCount = criticalCount; }

    public Integer getHighCount() { return highCount; }
    public void setHighCount(Integer highCount) { this.highCount = highCount; }

    public Integer getMediumCount() { return mediumCount; }
    public void setMediumCount(Integer mediumCount) { this.mediumCount = mediumCount; }

    public Integer getLowCount() { return lowCount; }
    public void setLowCount(Integer lowCount) { this.lowCount = lowCount; }

    public Integer getTotalFindings() { return totalFindings; }
    public void setTotalFindings(Integer totalFindings) { this.totalFindings = totalFindings; }

    public String getPredictedRisk() { return predictedRisk; }
    public void setPredictedRisk(String predictedRisk) { this.predictedRisk = predictedRisk; }

    public Double getPredictionConfidence() { return predictionConfidence; }
    public void setPredictionConfidence(Double predictionConfidence) { this.predictionConfidence = predictionConfidence; }

    public String getReportJsonPath() { return reportJsonPath; }
    public void setReportJsonPath(String reportJsonPath) { this.reportJsonPath = reportJsonPath; }

    public String getReportPdfPath() { return reportPdfPath; }
    public void setReportPdfPath(String reportPdfPath) { this.reportPdfPath = reportPdfPath; }

    public LocalDateTime getAnalysisDate() { return analysisDate; }
    public void setAnalysisDate(LocalDateTime analysisDate) { this.analysisDate = analysisDate; }

    public Long getAnalysisDurationMs() { return analysisDurationMs; }
    public void setAnalysisDurationMs(Long analysisDurationMs) { this.analysisDurationMs = analysisDurationMs; }

    // Méthodes utilitaires
    public String getScoreColor() {
        if (securityScore >= 70) return "#22c55e";
        if (securityScore >= 50) return "#eab308";
        return "#ef4444";
    }

    public String getFormattedDate() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
        return analysisDate.format(formatter);
    }
}