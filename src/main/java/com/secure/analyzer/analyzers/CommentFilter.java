package com.secure.analyzer.analyzers;

/**
 * CommentFilter - Filtre les commentaires du code source
 *
 * Permet d'ignorer les textes dans :
 * - Commentaires ligne //
 * - Commentaires bloc /* *\/
 * - Commentaires HTML <!-- -->
 */
public class CommentFilter {

    /**
     * Supprime les commentaires d'un contenu source
     * Retourne le contenu sans commentaires (uniquement le code)
     */
    public static String removeComments(String content) {
        if (content == null || content.isEmpty()) return content;

        StringBuilder result = new StringBuilder();
        boolean inLineComment = false;
        boolean inBlockComment = false;
        boolean inString = false;
        boolean inChar = false;
        boolean inHtmlComment = false;

        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            char next = (i + 1 < content.length()) ? content.charAt(i + 1) : 0;
            char nextNext = (i + 2 < content.length()) ? content.charAt(i + 2) : 0;

            // Gestion des chaînes de caractères
            if (!inLineComment && !inBlockComment && !inHtmlComment) {
                if (c == '"' && !inChar) {
                    inString = !inString;
                    result.append(c);
                    continue;
                }
                if (c == '\'' && !inString) {
                    inChar = !inChar;
                    result.append(c);
                    continue;
                }
            }

            // Détection début commentaire ligne //
            if (!inString && !inChar && !inBlockComment && !inHtmlComment && c == '/' && next == '/') {
                inLineComment = true;
                i++;
                continue;
            }

            // Détection début commentaire bloc /*
            if (!inString && !inChar && !inLineComment && !inHtmlComment && c == '/' && next == '*') {
                inBlockComment = true;
                i++;
                continue;
            }

            // Détection début commentaire HTML <!--
            if (!inString && !inChar && !inLineComment && !inBlockComment && c == '<' && next == '!' && nextNext == '-') {
                inHtmlComment = true;
                i += 2;
                continue;
            }

            // Fin commentaire ligne
            if (inLineComment && (c == '\n' || c == '\r')) {
                inLineComment = false;
                result.append('\n');
                continue;
            }

            // Fin commentaire bloc */
            if (inBlockComment && c == '*' && next == '/') {
                inBlockComment = false;
                i++;
                continue;
            }

            // Fin commentaire HTML -->
            if (inHtmlComment && c == '-' && next == '-' && nextNext == '>') {
                inHtmlComment = false;
                i += 2;
                continue;
            }

            // Ajout caractère si pas dans un commentaire
            if (!inLineComment && !inBlockComment && !inHtmlComment) {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Vérifie si une ligne est un commentaire
     */
    public static boolean isCommentLine(String line) {
        if (line == null) return true;
        String trimmed = line.trim();
        return trimmed.startsWith("//") || trimmed.startsWith("*")
                || trimmed.startsWith("/*") || trimmed.startsWith("* ")
                || trimmed.startsWith("<!--") || trimmed.startsWith("-->");
    }

    /**
     * Vérifie si une ligne est vide ou ne contient que des commentaires
     */
    public static boolean isLineIgnorable(String line) {
        if (line == null) return true;
        String trimmed = line.trim();
        return trimmed.isEmpty() || isCommentLine(line);
    }
}