package com.secure.analyzer.controllers;

import com.secure.analyzer.models.AnalysisHistory;
import com.secure.analyzer.services.HistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/history")
public class HistoryController {

    @Autowired
    private HistoryService historyService;

    /**
     * Page principale de l'historique
     */
    @GetMapping
    public String history(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String risk,
            Model model) {

        Page<AnalysisHistory> historyPage = historyService.getHistory(page, size, search, risk);

        model.addAttribute("historyPage", historyPage);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", historyPage.getTotalPages());
        model.addAttribute("search", search);
        model.addAttribute("riskFilter", risk);

        // Statistiques pour le dashboard
        model.addAttribute("stats", historyService.getStatistics());

        return "history";
    }

    /**
     * Voir le détail d'une analyse
     */
    @GetMapping("/{id}")
    public String viewAnalysis(@PathVariable Long id, Model model) {
        AnalysisHistory analysis = historyService.getAnalysisById(id);

        if (analysis == null) {
            return "redirect:/history?error=notfound";
        }

        model.addAttribute("analysis", analysis);
        return "history-detail";
    }

    /**
     * Supprimer une analyse (API)
     */
    @DeleteMapping("/{id}")
    @ResponseBody
    public Map<String, Object> deleteAnalysis(@PathVariable Long id) {
        Map<String, Object> response = new HashMap<>();
        boolean deleted = historyService.deleteAnalysis(id);
        response.put("success", deleted);
        response.put("message", deleted ? "Analyse supprimée" : "Analyse non trouvée");
        return response;
    }

    /**
     * Comparer deux analyses
     */
    @GetMapping("/compare")
    public String compare(
            @RequestParam Long id1,
            @RequestParam Long id2,
            Model model) {

        Map<String, Object> comparison = historyService.compareAnalyses(id1, id2);

        model.addAttribute("comparison", comparison);
        return "history-compare";
    }

    /**
     * API pour les statistiques (utilisée par les graphiques)
     */
    @GetMapping("/api/stats")
    @ResponseBody
    public Map<String, Object> getStats() {
        return historyService.getStatistics();
    }
}