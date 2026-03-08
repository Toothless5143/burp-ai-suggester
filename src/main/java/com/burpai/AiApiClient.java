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
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Thin wrapper around the OpenAI Chat Completions API.
 *
 * <p>The AI is asked to analyse a single HTTP request parameter and to return
 * a JSON array of attack suggestions. All networking happens synchronously on
 * the calling thread – callers should run this off the Swing EDT.
 */
public final class AiApiClient {

    private static final String OPENAI_URL = "https://api.openai.com/v1/chat/completions";
    private static final Duration TIMEOUT   = Duration.ofSeconds(30);
    private static final Gson GSON          = new Gson();

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .build();

    private AiApiClient() {}

    /**
     * Calls the OpenAI API and returns attack suggestions for the given parameter.
     *
     * @param url       the full request URL
     * @param method    the HTTP method
     * @param paramName the parameter name to analyse
     * @param paramValue the parameter value to analyse
     * @param paramType the parameter type (URL / Body / Cookie / JSON …)
     * @param apiKey    the OpenAI API key
     * @param model     the model to use (e.g. "gpt-4o", "gpt-3.5-turbo")
     * @return list of {@link AttackSuggestion} objects parsed from the AI response
     * @throws IOException          if the HTTP call fails
     * @throws InterruptedException if the thread is interrupted
     */
    public static List<AttackSuggestion> getSuggestions(String url, String method,
                                                        String paramName, String paramValue,
                                                        String paramType,
                                                        String apiKey, String model)
            throws IOException, InterruptedException {

        String prompt = buildPrompt(url, method, paramName, paramValue, paramType);
        String requestBody = buildRequestBody(model, prompt);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OPENAI_URL))
                .timeout(TIMEOUT)
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("OpenAI API returned HTTP " + response.statusCode()
                    + ": " + response.body());
        }

        return parseResponse(response.body());
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private static String buildPrompt(String url, String method,
                                      String paramName, String paramValue, String paramType) {
        return """
                You are an expert web application penetration tester.
                Analyse the following HTTP request parameter for security vulnerabilities.
                
                Request details:
                  URL    : %s
                  Method : %s
                  Parameter name  : %s
                  Parameter value : %s
                  Parameter type  : %s
                
                Respond ONLY with a valid JSON array (no markdown, no explanation).
                Each element must follow this exact schema:
                {
                  "attack_type": "<attack name>",
                  "risk_level":  "CRITICAL|HIGH|MEDIUM|LOW",
                  "description": "<one-sentence explanation>",
                  "payloads":    ["<payload1>", "<payload2>", "<payload3>"]
                }
                
                Provide 2–4 relevant attack types. If no attack is applicable, return [].
                """.formatted(url, method, paramName, paramValue, paramType);
    }

    private static String buildRequestBody(String model, String userPrompt) {
        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("temperature", 0.2);

        JsonArray messages = new JsonArray();

        JsonObject system = new JsonObject();
        system.addProperty("role", "system");
        system.addProperty("content", "You are a web application security expert specialising in penetration testing.");
        messages.add(system);

        JsonObject user = new JsonObject();
        user.addProperty("role", "user");
        user.addProperty("content", userPrompt);
        messages.add(user);

        body.add("messages", messages);
        return GSON.toJson(body);
    }

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
            // The original exception details: e.getClass().getSimpleName() + ": " + e.getMessage()
            System.err.println("[AI Suggester] Failed to parse AI response: "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return results;
    }
}
