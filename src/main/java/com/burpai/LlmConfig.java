package com.burpai;

import java.time.Duration;

/**
 * Immutable configuration for a local LLM endpoint (Ollama or any
 * OpenAI-compatible server).
 *
 * <p>Ollama defaults: host=localhost, port=11434, no API key required.
 * The {@link #endpointUrl()} builds the full chat-completions URL:
 * {@code http://<host>:<port>/v1/chat/completions}.
 */
public record LlmConfig(
        String   host,
        int      port,
        String   model,
        String   systemPrompt,
        String   apiKey,        // optional – leave blank for unauthenticated Ollama
        Duration timeout        // HTTP request timeout (default: 30 s for local LLMs)
) {
    // -----------------------------------------------------------------------
    // Defaults
    // -----------------------------------------------------------------------

    public static final String   DEFAULT_HOST    = "localhost";
    public static final int      DEFAULT_PORT    = 11434;
    public static final String   DEFAULT_MODEL   = "llama3.2";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    public static final String DEFAULT_SYSTEM_PROMPT =
            "You are an expert web application penetration tester. "
            + "Analyse the provided HTTP request parameter and return ONLY a valid JSON array "
            + "(no markdown fences, no explanation). "
            + "Each element must follow this exact schema:\n"
            + "{\n"
            + "  \"attack_type\": \"<attack name>\",\n"
            + "  \"risk_level\":  \"CRITICAL|HIGH|MEDIUM|LOW\",\n"
            + "  \"description\": \"<one-sentence explanation>\",\n"
            + "  \"payloads\":    [\"<payload1>\", \"<payload2>\", \"<payload3>\"]\n"
            + "}\n"
            + "Provide 2-4 relevant attack types. If no attack applies, return [].";

    // -----------------------------------------------------------------------
    // Compact canonical constructor – validates and normalises required fields
    // -----------------------------------------------------------------------

    public LlmConfig {
        if (host == null || host.isBlank())
            throw new IllegalArgumentException("LLM host must not be blank");
        host = host.trim();                       // normalise here so endpointUrl() is clean
        if (port < 1 || port > 65535)
            throw new IllegalArgumentException("LLM port must be 1-65535, got: " + port);
        if (model == null || model.isBlank())
            throw new IllegalArgumentException("LLM model must not be blank");
        if (systemPrompt == null || systemPrompt.isBlank())
            throw new IllegalArgumentException("System prompt must not be blank");
        apiKey  = (apiKey  == null) ? ""                : apiKey.trim();
        timeout = (timeout == null) ? DEFAULT_TIMEOUT   : timeout;
    }

    /** Full URL for the OpenAI-compatible chat completions endpoint. */
    public String endpointUrl() {
        return "http://" + host + ":" + port + "/v1/chat/completions";
    }

    /** Returns a default config pointing at a local Ollama instance. */
    public static LlmConfig defaultConfig() {
        return new LlmConfig(DEFAULT_HOST, DEFAULT_PORT, DEFAULT_MODEL,
                DEFAULT_SYSTEM_PROMPT, "", DEFAULT_TIMEOUT);
    }
}
