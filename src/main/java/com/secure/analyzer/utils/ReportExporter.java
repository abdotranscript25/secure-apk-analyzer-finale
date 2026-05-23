package com.secure.analyzer.utils;

import com.secure.analyzer.analyzers.UltimateAnalyzer;
import com.secure.analyzer.models.SecurityFinding;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

@Service
public class ReportExporter {
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
    /**
     * Exporte le rapport au format JSON
     */
    public static String exportToJson(UltimateAnalyzer.UltimateReport report) throws IOException {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date());
        String fileName = "report_" + report.packageName + "_" + timestamp + ".json";

        // Dossier de sortie
        File outputDir = new File(System.getProperty("user.dir"), "reports");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        File jsonFile = new File(outputDir, fileName);

        // Créer un objet JSON structuré
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        mapper.writeValue(jsonFile, createJsonStructure(report));

        return jsonFile.getAbsolutePath();
    }

    /**
     * Exporte le rapport au format PDF
     */
    public static String exportToPdf(UltimateAnalyzer.UltimateReport report) throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date());
        String fileName = "report_" + report.packageName + "_" + timestamp + ".pdf";

        File outputDir = new File(System.getProperty("user.dir"), "reports");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        File pdfFile = new File(outputDir, fileName);

        // Créer le PDF
        PdfWriter writer = new PdfWriter(pdfFile);
        PdfDocument pdfDoc = new PdfDocument(writer);
        Document document = new Document(pdfDoc);

        // Titre
        document.add(new Paragraph("🔒 RAPPORT DE SÉCURITÉ APK")
                .setFontSize(20)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER));

        document.add(new Paragraph("Généré le " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()))
                .setTextAlignment(TextAlignment.CENTER)
                .setFontSize(10));

        document.add(new Paragraph(" "));

        // Score
        int scoreColor = report.securityScore >= 70 ? 0x4CAF50 : (report.securityScore >= 50 ? 0xFF9800 : 0xD32F2F);
        document.add(new Paragraph("SCORE DE SÉCURITÉ")
                .setFontSize(16)
                .setBold()
                .setFontColor(ColorConstants.BLUE));

        Table scoreTable = new Table(UnitValue.createPercentArray(2)).useAllAvailableWidth();
        scoreTable.addCell(new Cell().add(new Paragraph("Score:")));
        scoreTable.addCell(new Cell().add(new Paragraph(report.securityScore + "/100")));
        scoreTable.addCell(new Cell().add(new Paragraph("Grade:")));
        scoreTable.addCell(new Cell().add(new Paragraph(report.securityGrade)));
        scoreTable.addCell(new Cell().add(new Paragraph("Risque:")));
        scoreTable.addCell(new Cell().add(new Paragraph(report.riskLevel)));
        document.add(scoreTable);

        document.add(new Paragraph(" "));

        // Statistiques
        document.add(new Paragraph("STATISTIQUES")
                .setFontSize(16)
                .setBold()
                .setFontColor(ColorConstants.BLUE));

        Table statsTable = new Table(UnitValue.createPercentArray(4)).useAllAvailableWidth();
        statsTable.addCell(new Cell().add(new Paragraph("🔴 CRITICAL")).setBackgroundColor(ColorConstants.RED));
        statsTable.addCell(new Cell().add(new Paragraph("🟠 HIGH")).setBackgroundColor(ColorConstants.ORANGE));
        statsTable.addCell(new Cell().add(new Paragraph("🟡 MEDIUM")).setBackgroundColor(ColorConstants.YELLOW));
        statsTable.addCell(new Cell().add(new Paragraph("🟢 LOW")).setBackgroundColor(ColorConstants.GREEN));
        statsTable.addCell(new Cell().add(new Paragraph(String.valueOf(report.criticalCount))));
        statsTable.addCell(new Cell().add(new Paragraph(String.valueOf(report.highCount))));
        statsTable.addCell(new Cell().add(new Paragraph(String.valueOf(report.mediumCount))));
        statsTable.addCell(new Cell().add(new Paragraph(String.valueOf(report.lowCount))));
        document.add(statsTable);

        document.add(new Paragraph(" "));

        // Informations APK
        document.add(new Paragraph("INFORMATIONS APK")
                .setFontSize(16)
                .setBold()
                .setFontColor(ColorConstants.BLUE));

        Table infoTable = new Table(UnitValue.createPercentArray(2)).useAllAvailableWidth();
        infoTable.addCell(new Cell().add(new Paragraph("Package:")));
        infoTable.addCell(new Cell().add(new Paragraph(report.packageName != null ? report.packageName : "Inconnu")));
        infoTable.addCell(new Cell().add(new Paragraph("Version:")));
        infoTable.addCell(new Cell().add(new Paragraph(report.versionName + " (" + report.versionCode + ")")));
        infoTable.addCell(new Cell().add(new Paragraph("Taille:")));
        infoTable.addCell(new Cell().add(new Paragraph(String.format("%.2f MB", report.fileSize / 1024.0 / 1024.0))));
        infoTable.addCell(new Cell().add(new Paragraph("SDK:")));
        infoTable.addCell(new Cell().add(new Paragraph("min=" + report.minSdk + " / target=" + report.targetSdk)));
        document.add(infoTable);

        document.add(new Paragraph(" "));

        // Vulnérabilités
        List<SecurityFinding> allFindings = report.getAllFindings();
        if (!allFindings.isEmpty()) {
            document.add(new Paragraph("VULNÉRABILITÉS DÉTECTÉES (" + allFindings.size() + ")")
                    .setFontSize(16)
                    .setBold()
                    .setFontColor(ColorConstants.RED));

            Table findingsTable = new Table(UnitValue.createPercentArray(new float[]{1, 2, 3})).useAllAvailableWidth();
            findingsTable.addHeaderCell(new Cell().add(new Paragraph("Sévérité")));
            findingsTable.addHeaderCell(new Cell().add(new Paragraph("Localisation")));
            findingsTable.addHeaderCell(new Cell().add(new Paragraph("Recommandation")));

            // Limiter à 50 findings pour la taille du PDF
            int count = 0;
            for (SecurityFinding finding : allFindings) {
                if (count++ > 50) {
                    findingsTable.addCell(new Cell().add(new Paragraph("...")));
                    findingsTable.addCell(new Cell().add(new Paragraph("... et " + (allFindings.size() - 50) + " autres")));
                    findingsTable.addCell(new Cell().add(new Paragraph("Voir rapport complet")));
                    break;
                }
                findingsTable.addCell(new Cell().add(new Paragraph(finding.getSeverity().toString())));
                findingsTable.addCell(new Cell().add(new Paragraph(finding.getLocation())));
                findingsTable.addCell(new Cell().add(new Paragraph(finding.getRecommendation())));
            }
            document.add(findingsTable);
        }

        document.add(new Paragraph(" "));

        // URLs trouvées
        if (!report.urlsFound.isEmpty()) {
            document.add(new Paragraph("URLs TROUVÉES (" + report.urlsFound.size() + ")")
                    .setFontSize(16)
                    .setBold()
                    .setFontColor(ColorConstants.ORANGE));

            for (String url : report.urlsFound) {
                document.add(new Paragraph("• " + url));
            }
        }

        // Recommandations
        document.add(new Paragraph("RECOMMANDATIONS")
                .setFontSize(16)
                .setBold()
                .setFontColor(ColorConstants.GREEN));

        if (report.criticalCount > 0) {
            document.add(new Paragraph("🔴 CRITICAL - Corriger immédiatement"));
            document.add(new Paragraph("   • Désactiver debuggable en production"));
            document.add(new Paragraph("   • Supprimer les clés API en dur"));
            document.add(new Paragraph("   • Chiffrer les données sensibles"));
        }

        if (report.highCount > 0) {
            document.add(new Paragraph("🟠 HIGH - Corriger rapidement"));
            document.add(new Paragraph("   • Désactiver allowBackup"));
            document.add(new Paragraph("   • Utiliser HTTPS"));
        }

        if (report.mediumCount > 0) {
            document.add(new Paragraph("🟡 MEDIUM - À revoir"));
            document.add(new Paragraph("   • Remplacer les algorithmes crypto faibles"));
            document.add(new Paragraph("   • Supprimer les logs sensibles"));
        }

        document.close();

        return pdfFile.getAbsolutePath();
    }

    private static Object createJsonStructure(UltimateAnalyzer.UltimateReport report) {
        java.util.Map<String, Object> json = new java.util.LinkedHashMap<>();

        json.put("report_date", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        json.put("file_name", report.fileName);
        json.put("package_name", report.packageName);
        json.put("version", report.versionName);
        json.put("version_code", report.versionCode);
        json.put("min_sdk", report.minSdk);
        json.put("target_sdk", report.targetSdk);
        json.put("file_size_mb", Math.round(report.fileSize / 1024.0 / 1024.0 * 100) / 100.0);
        json.put("total_classes", report.totalClasses);

        json.put("security_score", report.securityScore);
        json.put("security_grade", report.securityGrade);
        json.put("risk_level", report.riskLevel);

        java.util.Map<String, Integer> counts = new java.util.LinkedHashMap<>();
        counts.put("critical", report.criticalCount);
        counts.put("high", report.highCount);
        counts.put("medium", report.mediumCount);
        counts.put("low", report.lowCount);
        counts.put("total", report.totalFindings);
        json.put("severity_counts", counts);

        // URLs
        json.put("urls_found", report.urlsFound);

        // Vulnerabilités par catégorie
        java.util.Map<String, java.util.List<java.util.Map<String, Object>>> categories = new java.util.LinkedHashMap<>();

        addFindingsToJson(categories, "Manifest", report.manifestFindings);
        addFindingsToJson(categories, "Code", report.codeFindings);
        addFindingsToJson(categories, "Network", report.networkFindings);
        addFindingsToJson(categories, "Crypto", report.cryptoFindings);
        addFindingsToJson(categories, "Data", report.dataFindings);

        json.put("findings_by_category", categories);

        // Groupement par catégorie MASVS
        java.util.Map<String, java.util.List<java.util.Map<String, Object>>> masvsMap = new java.util.LinkedHashMap<>();
        for (SecurityFinding f : report.getAllFindings()) {
            String masvsCode = f.getMasvsCode(); // ex: "MASVS-CRYPTO"
            masvsMap.computeIfAbsent(masvsCode, k -> new java.util.ArrayList<>())
                    .add(java.util.Map.of(
                            "severity",       f.getSeverity().toString(),
                            "type",           f.getType().toString(),
                            "location",       f.getLocation(),
                            "recommendation", f.getRecommendation()
                    ));
        }
        json.put("findings_by_masvs", masvsMap);

        return json;
    }

    private static void addFindingsToJson(java.util.Map<String, java.util.List<java.util.Map<String, Object>>> categories,
                                          String category, List<SecurityFinding> findings) {
        if (findings.isEmpty()) return;

        java.util.List<java.util.Map<String, Object>> items = new java.util.ArrayList<>();
        for (SecurityFinding f : findings) {
            java.util.Map<String, Object> item = new java.util.LinkedHashMap<>();
            item.put("severity", f.getSeverity().toString());
            item.put("location", f.getLocation());
            item.put("evidence", f.getRawValueSnippet());
            item.put("recommendation", f.getRecommendation());
            items.add(item);
        }
        categories.put(category, items);
    }
}