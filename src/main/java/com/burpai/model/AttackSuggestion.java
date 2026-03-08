package com.burpai.model;

import java.util.List;

/**
 * Represents a single attack suggestion for a parameter.
 * May originate from built-in rules or from an AI API response.
 */
public class AttackSuggestion {

    private final String attackName;
    private final String riskLevel;
    private final String description;
    private final List<String> payloads;
    private final boolean fromAi;

    public AttackSuggestion(String attackName, String riskLevel, String description,
                            List<String> payloads, boolean fromAi) {
        this.attackName  = attackName;
        this.riskLevel   = riskLevel;
        this.description = description;
        this.payloads    = List.copyOf(payloads);
        this.fromAi      = fromAi;
    }

    /** Convenience constructor from a built-in AttackType enum value. */
    public static AttackSuggestion fromAttackType(AttackType type) {
        return new AttackSuggestion(
                type.getDisplayName(),
                type.getRiskLevel(),
                type.getDescription(),
                type.getSamplePayloads(),
                false
        );
    }

    public String getAttackName()  { return attackName; }
    public String getRiskLevel()   { return riskLevel; }
    public String getDescription() { return description; }
    public List<String> getPayloads() { return payloads; }
    public boolean isFromAi()      { return fromAi; }

    /** Returns a hex colour suitable for Swing HTML based on risk level. */
    public String getRiskColour() {
        return switch (riskLevel) {
            case "CRITICAL" -> "#9b0000";
            case "HIGH"     -> "#cc3300";
            case "MEDIUM"   -> "#e67e00";
            default         -> "#666666";
        };
    }

    /** Returns an emoji indicator based on risk level. */
    public String getRiskEmoji() {
        return switch (riskLevel) {
            case "CRITICAL" -> "🔴";
            case "HIGH"     -> "🟠";
            case "MEDIUM"   -> "🟡";
            default         -> "⚪";
        };
    }
}
