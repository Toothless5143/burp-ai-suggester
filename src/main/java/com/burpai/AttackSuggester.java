package com.burpai;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.burpai.model.AttackSuggestion;
import com.burpai.model.AttackType;
import com.burpai.model.ParameterAnalysis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Core engine that analyses HTTP request parameters and produces attack suggestions.
 *
 * <p>Two operating modes are supported:
 * <ol>
 *   <li><b>Built-in rules</b> – keyword and value heuristics (always available, no key required).</li>
 *   <li><b>AI mode</b>    – results are enriched by calling the OpenAI Chat API when a key is set.</li>
 * </ol>
 */
public class AttackSuggester {

    // -----------------------------------------------------------------------
    // Keyword sets per attack type (lower-cased, matched as substrings)
    // -----------------------------------------------------------------------

    private static final Set<String> SQL_NAMES = Set.of(
            "id", "uid", "user_id", "product_id", "item_id", "account_id", "order_id",
            "cat", "category", "page", "num", "number", "no", "nr",
            "order", "sort", "orderby", "sortby", "by",
            "type", "select", "search", "q", "query", "filter", "where", "from",
            "name", "username", "user", "login", "email", "account",
            "pass", "password", "pwd", "key", "code", "ref", "token",
            "product", "item", "article", "post", "entry", "record", "row", "data",
            "invoice", "ticket", "report"
    );

    private static final Set<String> XSS_NAMES = Set.of(
            "message", "comment", "content", "text", "body", "desc", "description",
            "title", "name", "search", "q", "query", "callback", "jsonp",
            "url", "redirect", "ref", "return", "returnurl", "back", "next",
            "feedback", "review", "post", "topic", "subject", "msg", "input",
            "data", "value", "note", "display", "label", "header", "footer", "info",
            "about", "bio", "signature", "username", "fullname", "firstname", "lastname",
            "address", "location", "city", "country", "phone", "email"
    );

    private static final Set<String> CMD_NAMES = Set.of(
            "cmd", "command", "exec", "execute", "run", "shell", "bash", "sh", "powershell",
            "file", "filename", "filepath",
            "ping", "host", "ip", "address", "server", "domain",
            "nslookup", "dig", "traceroute", "netstat",
            "program", "process", "binary", "exe", "bin",
            "action", "operation", "task",
            "script", "util", "tool", "log", "dir"
    );

    private static final Set<String> PATH_NAMES = Set.of(
            "file", "filename", "filepath", "path", "dir", "directory", "folder",
            "doc", "document", "page", "template", "theme", "layout", "view",
            "load", "include", "download", "upload", "open", "read", "write",
            "resource", "asset", "media", "image", "img", "photo", "avatar",
            "report", "export", "import", "backup", "config", "conf",
            "log", "logfile", "access", "error", "debug"
    );

    private static final Set<String> SSRF_NAMES = Set.of(
            "url", "uri", "href", "src", "source", "target", "dest", "destination",
            "endpoint", "api", "service", "server", "host", "domain",
            "webhook", "callback", "notify", "notification",
            "redirect", "link", "goto", "next", "forward",
            "fetch", "proxy", "gateway", "request", "ping",
            "feed", "rss", "atom", "image", "img", "icon", "favicon",
            "import", "load", "inject", "embed", "iframe", "include"
    );

    private static final Set<String> REDIRECT_NAMES = Set.of(
            "redirect", "redirect_url", "redirect_to", "redirecturl", "redirectto",
            "return", "return_url", "returnurl", "returnto",
            "back", "next", "continue", "forward", "url", "goto",
            "destination", "dest", "target", "site", "out", "exit",
            "logout", "from", "to", "login", "auth", "signin",
            "ref", "referrer", "referer", "origin"
    );

    private static final Set<String> SSTI_NAMES = Set.of(
            "template", "theme", "layout", "view", "render", "format",
            "output", "display", "engine", "tpl", "tmpl",
            "page", "lang", "language", "locale"
    );

    private static final Set<String> IDOR_NAMES = Set.of(
            "id", "uid", "user_id", "account_id", "profile_id", "order_id", "doc_id",
            "file_id", "post_id", "record_id", "object_id", "item_id", "product_id",
            "invoice_id", "ticket_id", "message_id", "chat_id", "group_id",
            "key", "ref", "reference", "no", "number", "num", "nr", "index"
    );

    private static final Set<String> LFI_NAMES = Set.of(
            "file", "filename", "page", "include", "template", "module",
            "lang", "language", "locale", "i18n", "load", "path", "view",
            "doc", "document", "script", "style", "layout", "require", "lib"
    );

    private static final Set<String> LDAP_NAMES = Set.of(
            "username", "user", "login", "name", "uid", "cn", "dn",
            "member", "group", "role", "org", "account", "id",
            "email", "mail", "phone", "department", "employee"
    );

    private static final Set<String> HEADER_NAMES = Set.of(
            "useragent", "user_agent", "x_forwarded_for", "x-forwarded-for",
            "referer", "referrer", "origin", "host", "content_type"
    );

    /**
     * Keywords specifically associated with NoSQL databases / object query patterns.
     * These are intentionally narrower than SQL keywords to avoid duplicate suggestions.
     */
    private static final Set<String> NOSQL_NAMES = Set.of(
            "filter", "query", "where", "match", "find", "aggregate",
            "collection", "document", "field", "operator",
            "db", "database", "mongo", "redis", "elastic", "couch",
            "sort", "limit", "skip", "projection"
    );

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Analyses every parameter in the request.
     *
     * @param request   the HTTP request to analyse
     * @param llmConfig LLM connection config; pass {@code null} to use built-in rules only
     * @return a list of {@link ParameterAnalysis} objects, one per parameter
     */
    public List<ParameterAnalysis> analyze(HttpRequest request, LlmConfig llmConfig) {
        List<ParsedHttpParameter> params = request.parameters();
        String url    = request.url();
        String method = request.method();

        List<ParameterAnalysis> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (ParsedHttpParameter param : params) {
            String name  = param.name();
            String value = param.value();
            String type  = friendlyType(param.type());

            // Deduplicate by name+type to avoid repetition (e.g. same cookie name appearing twice)
            String key = name + "|" + type;
            if (!seen.add(key)) continue;

            List<AttackSuggestion> suggestions = buildSuggestions(name, value, type, url, method, param.type());

            // Optionally enrich with AI
            if (llmConfig != null) {
                try {
                    List<AttackSuggestion> aiSuggestions =
                            AiApiClient.getSuggestions(url, method, name, value, type, llmConfig);
                    suggestions = merge(suggestions, aiSuggestions);
                } catch (Exception e) {
                    // If AI call fails, fall back to built-in suggestions only
                    System.err.println("[AI Suggester] LLM call failed for param '"
                            + name + "': " + e.getMessage());
                }
            }

            results.add(new ParameterAnalysis(name, value, type, suggestions));
        }

        return results;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private List<AttackSuggestion> buildSuggestions(String name, String value, String friendlyType,
                                                    String url, String method,
                                                    HttpParameterType rawType) {
        String lName  = name.toLowerCase();
        String lValue = value.toLowerCase();
        List<AttackSuggestion> list = new ArrayList<>();

        // ----- SQL Injection -----
        if (matchesAny(lName, SQL_NAMES) || isNumeric(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.SQL_INJECTION));
        }

        // ----- NoSQL Injection -----
        // Suggest for JSON-type params OR names that specifically hint at NoSQL usage
        if (rawType == HttpParameterType.JSON || matchesAny(lName, NOSQL_NAMES)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.NOSQL_INJECTION));
        }

        // ----- XSS -----
        if (matchesAny(lName, XSS_NAMES) || isTextLike(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.XSS));
        }

        // ----- Command Injection -----
        if (matchesAny(lName, CMD_NAMES)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.COMMAND_INJECTION));
        }

        // ----- Path Traversal -----
        if (matchesAny(lName, PATH_NAMES) || looksLikeFilePath(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.PATH_TRAVERSAL));
        }

        // ----- SSRF -----
        if (matchesAny(lName, SSRF_NAMES) || looksLikeUrl(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.SSRF));
        }

        // ----- Open Redirect -----
        if (matchesAny(lName, REDIRECT_NAMES) || looksLikeUrl(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.OPEN_REDIRECT));
        }

        // ----- SSTI -----
        if (matchesAny(lName, SSTI_NAMES)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.SSTI));
        }

        // ----- XXE -----
        // Suggest when Content-Type is XML or param type is XML
        if (rawType == HttpParameterType.XML || rawType == HttpParameterType.XML_ATTRIBUTE
                || lValue.contains("<?xml") || lValue.contains("<!doctype")) {
            list.add(AttackSuggestion.fromAttackType(AttackType.XXE));
        }

        // ----- LDAP Injection -----
        if (matchesAny(lName, LDAP_NAMES)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.LDAP_INJECTION));
        }

        // ----- IDOR -----
        if (matchesAny(lName, IDOR_NAMES) && (isNumeric(value) || isUuid(value))) {
            list.add(AttackSuggestion.fromAttackType(AttackType.IDOR));
        }

        // ----- LFI / RFI -----
        if (matchesAny(lName, LFI_NAMES) || looksLikeFilePath(value)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.FILE_INCLUSION));
        }

        // ----- HTTP Header Injection -----
        if (matchesAny(lName, HEADER_NAMES)) {
            list.add(AttackSuggestion.fromAttackType(AttackType.HEADER_INJECTION));
        }

        // Deduplicate by attack name
        List<AttackSuggestion> deduped = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (AttackSuggestion s : list) {
            if (seen.add(s.getAttackName())) {
                deduped.add(s);
            }
        }
        return deduped;
    }

    /** Merges built-in suggestions with AI suggestions, AI items taking priority. */
    private List<AttackSuggestion> merge(List<AttackSuggestion> builtIn, List<AttackSuggestion> ai) {
        List<AttackSuggestion> result = new ArrayList<>(ai);
        Set<String> aiNames = new HashSet<>();
        for (AttackSuggestion s : ai) aiNames.add(s.getAttackName());

        for (AttackSuggestion s : builtIn) {
            if (!aiNames.contains(s.getAttackName())) {
                result.add(s);
            }
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Utility predicates
    // -----------------------------------------------------------------------

    /** Returns true if the parameter name contains any keyword from the set (as substring). */
    private boolean matchesAny(String lName, Set<String> keywords) {
        if (keywords.contains(lName)) return true;
        for (String kw : keywords) {
            if (lName.contains(kw)) return true;
        }
        return false;
    }

    private boolean isNumeric(String value) {
        if (value == null || value.isBlank()) return false;
        try { Long.parseLong(value.trim()); return true; }
        catch (NumberFormatException e) { return false; }
    }

    private boolean isUuid(String value) {
        if (value == null) return false;
        return value.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }

    private boolean isTextLike(String value) {
        if (value == null || value.isBlank()) return false;
        // Looks like a human-readable string (contains letters, spaces, or HTML)
        return value.length() > 1 && value.matches(".*[a-zA-Z].*");
    }

    private boolean looksLikeUrl(String value) {
        if (value == null || value.isBlank()) return false;
        String lv = value.toLowerCase();
        return lv.startsWith("http://") || lv.startsWith("https://")
                || lv.startsWith("//") || lv.startsWith("ftp://")
                || lv.matches(".*\\.(com|org|net|io|co|uk|de|fr|app|dev)(/?|/.*)");
    }

    private boolean looksLikeFilePath(String value) {
        if (value == null || value.isBlank()) return false;
        return value.contains("/") || value.contains("\\")
                || value.contains("..")
                || value.matches(".*\\.(php|asp|aspx|jsp|html|htm|txt|log|conf|cfg|xml|json|ini)$");
    }

    private String friendlyType(HttpParameterType type) {
        return switch (type) {
            case URL               -> "URL";
            case BODY              -> "Body";
            case COOKIE            -> "Cookie";
            case XML               -> "XML";
            case XML_ATTRIBUTE     -> "XML Attr";
            case MULTIPART_ATTRIBUTE -> "Multipart";
            case JSON              -> "JSON";
            default                -> "Unknown";
        };
    }
}
