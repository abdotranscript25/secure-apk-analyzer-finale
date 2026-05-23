package com.secure.analyzer.controllers;

import com.secure.analyzer.analyzers.UltimateAnalyzer;
import com.secure.analyzer.classifiers.RiskPredictor;
import com.secure.analyzer.services.HistoryService;
import com.secure.analyzer.utils.ReportExporter;
import com.secure.analyzer.models.FindingType;
import com.secure.analyzer.models.SecurityFinding;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.core.io.Resource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.secure.analyzer.ai.AIBehaviorAnalyzer;

import java.nio.file.*;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

@Controller
public class APKAnalyzerController {

    private static final String UPLOAD_DIR = "uploads/";

    // Stocker le dernier rapport généré pour l'export
    private UltimateAnalyzer.UltimateReport lastExportedReport;
    private String lastExportedFileName;

    @Autowired
    private HistoryService historyService;

    // ═══════════════════════════════════════════════════════════════
    // PAGES WEB
    // ═══════════════════════════════════════════════════════════════

    /**
     * Page d'accueil - Upload d'APK
     */
    @GetMapping("/")
    public String index() {
        return "index";
    }

    /**
     * Page À propos / Présentation du projet
     */
    @GetMapping("/about")
    public String about() {
        return "about";
    }

    /**
     * Analyse d'un fichier APK
     */
    @PostMapping("/analyze")
    public String analyze(@RequestParam("file") MultipartFile file, Model model) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. Create upload folder
            Files.createDirectories(Paths.get(UPLOAD_DIR));

            // 2. Save APK
            String apkPath = UPLOAD_DIR + System.currentTimeMillis()
                    + "_" + file.getOriginalFilename();

            file.transferTo(Paths.get(apkPath));

            System.out.println("📱 Analyse de: " + apkPath);

            // 3. Static analysis
            UltimateAnalyzer.UltimateReport report =
                    UltimateAnalyzer.analyze(apkPath);

            AIBehaviorAnalyzer.AIResult ai =
                    AIBehaviorAnalyzer.analyze(report);

            // 4. AI prediction
            RiskPredictor.PredictionResult prediction =
                    RiskPredictor.predict(report);

            // 5. Delete temp file
            try {
                Files.deleteIfExists(Paths.get(apkPath));
            } catch (Exception e) {
                System.err.println("⚠ Impossible de supprimer APK temporaire");
            }

            // 6. Store report for immediate export
            lastExportedReport = report;
            lastExportedFileName = file.getOriginalFilename();

            // 7. Sauvegarde dans l'historique
            try {
                // Exporter automatiquement en JSON et PDF pour l'historique
                String jsonPath = ReportExporter.exportToJson(report);
                String pdfPath = ReportExporter.exportToPdf(report);
                long analysisDuration = System.currentTimeMillis() - startTime;

                historyService.saveAnalysis(report, prediction, jsonPath, pdfPath, analysisDuration);
                System.out.println("✅ Analyse sauvegardée dans l'historique");

            } catch (Exception e) {
                System.err.println("⚠ Erreur lors de la sauvegarde historique: " + e.getMessage());
                e.printStackTrace();
                // Ne pas bloquer l'affichage du rapport
            }

            // 8. Send data to HTML
            model.addAttribute("report", report);
            model.addAttribute("ai", ai);
            model.addAttribute("predictedRisk", prediction.riskCategory);
            model.addAttribute("predictionConfidence", prediction.confidenceScore);

            // 9. Groupement MASVS pour Thymeleaf
            Map<FindingType.MasvsCategory, List<SecurityFinding>> mavsGrouped = report.getAllFindings()
                    .stream()
                    .collect(java.util.stream.Collectors.groupingBy(
                            SecurityFinding::getMasvsCategory,
                            java.util.LinkedHashMap::new,
                            java.util.stream.Collectors.toList()
                    ));
            model.addAttribute("mavsGrouped", mavsGrouped);

            return "report";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // ENDPOINTS D'EXPORT PDF / JSON
    // ═══════════════════════════════════════════════════════════════

    /**
     * Exporte le rapport au format PDF
     */
    @PostMapping("/export/pdf")
    @ResponseBody
    public Map<String, Object> exportPdf() {
        Map<String, Object> response = new HashMap<>();
        try {
            if (lastExportedReport == null) {
                response.put("success", false);
                response.put("error", "Aucun rapport disponible. Veuillez d'abord analyser un APK.");
                return response;
            }

            String pdfPath = ReportExporter.exportToPdf(lastExportedReport);
            response.put("success", true);
            response.put("path", pdfPath);
            response.put("message", "Rapport PDF généré avec succès");

            System.out.println("✅ Rapport PDF exporté: " + pdfPath);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors de l'export PDF: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("error", "Erreur lors de la génération du PDF: " + e.getMessage());
        }
        return response;
    }

    /**
     * Exporte le rapport au format JSON
     */
    @PostMapping("/export/json")
    @ResponseBody
    public Map<String, Object> exportJson() {
        Map<String, Object> response = new HashMap<>();
        try {
            if (lastExportedReport == null) {
                response.put("success", false);
                response.put("error", "Aucun rapport disponible. Veuillez d'abord analyser un APK.");
                return response;
            }

            String jsonPath = ReportExporter.exportToJson(lastExportedReport);
            response.put("success", true);
            response.put("path", jsonPath);
            response.put("message", "Rapport JSON généré avec succès");

            System.out.println("✅ Rapport JSON exporté: " + jsonPath);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors de l'export JSON: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("error", "Erreur lors de la génération du JSON: " + e.getMessage());
        }
        return response;
    }

    /**
     * Télécharge le fichier PDF
     */
    @GetMapping("/download/pdf")
    public ResponseEntity<Resource> downloadPdf() {
        try {
            if (lastExportedReport == null) {
                throw new RuntimeException("Aucun rapport disponible");
            }

            String pdfPath = ReportExporter.exportToPdf(lastExportedReport);
            File file = new File(pdfPath);

            if (!file.exists()) {
                throw new RuntimeException("Le fichier PDF n'existe pas: " + pdfPath);
            }

            Resource resource = new FileSystemResource(file);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + file.getName() + "\"")
                    .body(resource);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors du téléchargement PDF: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Télécharge le fichier JSON
     */
    @GetMapping("/download/json")
    public ResponseEntity<Resource> downloadJson() {
        try {
            if (lastExportedReport == null) {
                throw new RuntimeException("Aucun rapport disponible");
            }

            String jsonPath = ReportExporter.exportToJson(lastExportedReport);
            File file = new File(jsonPath);

            if (!file.exists()) {
                throw new RuntimeException("Le fichier JSON n'existe pas: " + jsonPath);
            }

            Resource resource = new FileSystemResource(file);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + file.getName() + "\"")
                    .body(resource);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors du téléchargement JSON: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Télécharge un PDF depuis l'historique par ID
     */
    @GetMapping("/download/pdf/{id}")
    public ResponseEntity<Resource> downloadPdfFromHistory(@PathVariable Long id) {
        try {
            var analysis = historyService.getAnalysisById(id);
            if (analysis == null || analysis.getReportPdfPath() == null) {
                return ResponseEntity.notFound().build();
            }

            File file = new File(analysis.getReportPdfPath());
            if (!file.exists()) {
                return ResponseEntity.notFound().build();
            }

            Resource resource = new FileSystemResource(file);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + file.getName() + "\"")
                    .body(resource);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors du téléchargement PDF: " + e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Télécharge un JSON depuis l'historique par ID
     */
    @GetMapping("/download/json/{id}")
    public ResponseEntity<Resource> downloadJsonFromHistory(@PathVariable Long id) {
        try {
            var analysis = historyService.getAnalysisById(id);
            if (analysis == null || analysis.getReportJsonPath() == null) {
                return ResponseEntity.notFound().build();
            }

            File file = new File(analysis.getReportJsonPath());
            if (!file.exists()) {
                return ResponseEntity.notFound().build();
            }

            Resource resource = new FileSystemResource(file);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + file.getName() + "\"")
                    .body(resource);

        } catch (Exception e) {
            System.err.println("❌ Erreur lors du téléchargement JSON: " + e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
}