package com.burpai.model;

import java.util.List;

/**
 * Holds the analysis result for a single HTTP request parameter.
 */
public class ParameterAnalysis {

    private final String paramName;
    private final String paramValue;
    private final String paramType;
    private final List<AttackSuggestion> suggestions;

    public ParameterAnalysis(String paramName, String paramValue,
                             String paramType, List<AttackSuggestion> suggestions) {
        this.paramName   = paramName;
        this.paramValue  = paramValue;
        this.paramType   = paramType;
        this.suggestions = List.copyOf(suggestions);
    }

    public String getParamName()  { return paramName; }
    public String getParamValue() { return paramValue; }
    public String getParamType()  { return paramType; }
    public List<AttackSuggestion> getSuggestions() { return suggestions; }

    /** Returns a short label for display that lists suggested attack names. */
    public String getSuggestionsLabel() {
        if (suggestions.isEmpty()) return "None detected";
        StringBuilder sb = new StringBuilder();
        for (AttackSuggestion s : suggestions) {
            if (!sb.isEmpty()) sb.append(", ");
            sb.append(s.getAttackName());
        }
        return sb.toString();
    }

    /** Returns the highest risk level found across all suggestions. */
    public String getHighestRisk() {
        boolean hasCritical = suggestions.stream().anyMatch(s -> "CRITICAL".equals(s.getRiskLevel()));
        boolean hasHigh     = suggestions.stream().anyMatch(s -> "HIGH".equals(s.getRiskLevel()));
        boolean hasMedium   = suggestions.stream().anyMatch(s -> "MEDIUM".equals(s.getRiskLevel()));
        if (hasCritical) return "CRITICAL";
        if (hasHigh)     return "HIGH";
        if (hasMedium)   return "MEDIUM";
        if (!suggestions.isEmpty()) return "LOW";
        return "NONE";
    }
}
