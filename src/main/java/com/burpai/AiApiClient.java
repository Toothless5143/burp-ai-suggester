package com.burpai;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.burpai.model.AttackSuggestion;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * Client for any OpenAI-compatible local LLM (Ollama, LM Studio, llama.cpp, etc.).
 *
 * <p>All connection details (host, port, model, system prompt) come from a
 * {@link LlmConfig} object so nothing is hardcoded. Networking happens
 * synchronously on the calling thread — callers must run this off the Swing EDT.
 */
public final class AiApiClient {

    private static final Gson GSON = new Gson();

    // The HttpClient itself has no fixed timeout; per-request timeouts come from LlmConfig.
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder().build();

    private AiApiClient() {}

    /**
     * Calls the local LLM and returns attack suggestions for one HTTP parameter.
     *
     * @param requestUrl  the full URL of the HTTP request being analysed
     * @param method      the HTTP method (GET, POST, …)
     * @param paramName   the parameter name to analyse
     * @param paramValue  the parameter value to analyse
     * @param paramType   the parameter type label (URL / Body / Cookie / JSON …)
     * @param config      LLM connection config (host, port, model, system prompt)
     * @return list of {@link AttackSuggestion} objects parsed from the LLM response
     * @throws IOException          if the HTTP call fails
     * @throws InterruptedException if the thread is interrupted
     */
    public static List<AttackSuggestion> getSuggestions(String requestUrl, String method,
                                                        String paramName, String paramValue,
                                                        String paramType,
                                                        LlmConfig config)
            throws IOException, InterruptedException {

        String userPrompt   = buildUserPrompt(requestUrl, method, paramName, paramValue, paramType);
        String requestBody  = buildRequestBody(config, userPrompt);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.endpointUrl()))
                .timeout(config.timeout())
                .header("Content-Type", "application/json");

        // Attach Authorization header only when an API key is provided
        String apiKey = config.apiKey();
        if (!apiKey.isBlank()) {
            builder.header("Authorization", "Bearer " + apiKey);
        }

        HttpRequest request = builder
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("LLM endpoint returned HTTP " + response.statusCode()
                    + ": " + response.body());
        }

        return parseResponse(response.body());
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /** Builds the user-facing prompt with the parameter details. */
    private static String buildUserPrompt(String requestUrl, String method,
                                          String paramName, String paramValue, String paramType) {
        return "Analyse the following HTTP request parameter for security vulnerabilities.\n\n"
                + "Request details:\n"
                + "  URL    : " + requestUrl + "\n"
                + "  Method : " + method + "\n"
                + "  Parameter name  : " + paramName + "\n"
                + "  Parameter value : " + paramValue + "\n"
                + "  Parameter type  : " + paramType + "\n";
    }

    /** Builds the JSON body for the chat completions request. */
    private static String buildRequestBody(LlmConfig config, String userPrompt) {
        JsonObject body = new JsonObject();
        body.addProperty("model", config.model());
        body.addProperty("temperature", 0.2);
        body.addProperty("stream", false);

        JsonArray messages = new JsonArray();

        JsonObject system = new JsonObject();
        system.addProperty("role", "system");
        system.addProperty("content", config.systemPrompt());
        messages.add(system);

        JsonObject user = new JsonObject();
        user.addProperty("role", "user");
        user.addProperty("content", userPrompt);
        messages.add(user);

        body.add("messages", messages);
        return GSON.toJson(body);
    }

    /** Parses the chat completions JSON response into {@link AttackSuggestion} objects. */
    private static List<AttackSuggestion> parseResponse(String responseBody) {
        List<AttackSuggestion> results = new ArrayList<>();
        try {
            JsonObject root = GSON.fromJson(responseBody, JsonObject.class);
            String content = root.getAsJsonArray("choices")
                    .get(0).getAsJsonObject()
                    .getAsJsonObject("message")
                    .get("content").getAsString();

            // Strip any accidental markdown fences
            content = content.trim();
            if (content.startsWith("```")) {
                content = content.replaceAll("(?s)^```[a-zA-Z]*\\n?", "").replaceAll("```$", "").trim();
            }

            JsonArray arr = GSON.fromJson(content, JsonArray.class);
            for (JsonElement el : arr) {
                JsonObject obj = el.getAsJsonObject();

                String attackName  = obj.get("attack_type").getAsString();
                String riskLevel   = obj.has("risk_level")  ? obj.get("risk_level").getAsString()  : "MEDIUM";
                String description = obj.has("description") ? obj.get("description").getAsString() : "";

                List<String> payloads = new ArrayList<>();
                if (obj.has("payloads")) {
                    for (JsonElement p : obj.getAsJsonArray("payloads")) {
                        payloads.add(p.getAsString());
                    }
                }

                results.add(new AttackSuggestion(attackName, riskLevel, description, payloads, true));
            }
        } catch (Exception e) {
            // If parsing fails, return an empty list so callers fall back to built-in rules.
            System.err.println("[AI Suggester] Failed to parse LLM response: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return results;
    }
}
