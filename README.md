# burp-ai-suggester

A Burp Suite extension (Montoya API) that analyses every HTTP request parameter and suggests potential attack vectors — complete with 2–3 sample payloads per attack type.

---

## Features

| Feature | Detail |
|---|---|
| **13 attack types covered** | SQL Injection, XSS, OS Command Injection, Path Traversal, SSRF, Open Redirect, SSTI, XXE, LDAP Injection, NoSQL Injection, IDOR, LFI/RFI, HTTP Header Injection |
| **Built-in rules** | Keyword heuristics on parameter names + value patterns – works entirely offline |
| **AI-enhanced mode** | Optionally uses the OpenAI Chat API for richer, context-aware suggestions |
| **Right-click integration** | "AI Suggester: Analyze Request" context menu item in Proxy, Repeater, Target, Intruder |
| **Dedicated suite tab** | "AI Suggester" tab in the Burp toolbar with an Analyzer and Settings sub-tab |
| **Per-parameter detail** | Coloured risk levels (CRITICAL / HIGH / MEDIUM), descriptions, and copy-ready payloads |

---

## Requirements

| Tool | Version |
|---|---|
| Java | 11 or newer (17 recommended) |
| Maven | 3.6+ |
| Burp Suite | Professional or Community Edition 2022.9.1+ (Montoya API) |

---

## Build

```bash
git clone https://github.com/Toothless5143/burp-ai-suggester.git
cd burp-ai-suggester
mvn package
```

The shaded JAR (with all dependencies bundled) is written to:

```
target/burp-ai-suggester-1.0.0.jar
```

---

## Load in Burp Suite

1. Open Burp Suite.  
2. Go to **Extensions → Installed → Add**.  
3. Set **Extension type** to **Java**.  
4. Click **Select file…** and choose `target/burp-ai-suggester-1.0.0.jar`.  
5. Click **Next** – the extension loads and an **"AI Suggester"** tab appears in the Burp toolbar.

---

## Usage

### Analyse a request

1. Browse to any site via Burp Proxy, open a request in **Repeater**, **Target**, or **Intruder**.  
2. **Right-click the request** and select **AI Suggester: Analyze Request**.  
3. Switch to the **AI Suggester** tab → **Analyzer** sub-tab.  
4. The request is analysed and each detected parameter is listed with its suggested attacks.  
5. Click a row in the parameter table to see full attack descriptions and sample payloads.

### AI-enhanced mode (optional)

1. Go to the **AI Suggester → Settings** tab.  
2. Select **AI-enhanced** and enter your **OpenAI API key** (`sk-…`).  
3. Choose a model (`gpt-4o`, `gpt-4-turbo`, `gpt-4`, `gpt-3.5-turbo`).  
4. Click **Test Connection** to verify the key, then **Save**.  
5. Re-run the analysis – each parameter now gets an additional `✨ AI` badge with richer suggestions.

> Your API key is stored in memory only and is not persisted between Burp sessions.

---

## Attack types detected

| Attack | Risk | Parameter name signals |
|---|---|---|
| SQL Injection | 🟠 HIGH | `id`, `search`, `query`, `user`, `order`, … |
| NoSQL Injection | 🟠 HIGH | JSON-type params, same keywords as SQLi |
| Cross-Site Scripting | 🟠 HIGH | `message`, `comment`, `name`, `q`, `callback`, … |
| OS Command Injection | 🔴 CRITICAL | `cmd`, `exec`, `ping`, `file`, `path`, … |
| Path Traversal | 🟠 HIGH | `file`, `dir`, `path`, `template`, `page`, … |
| SSRF | 🟠 HIGH | `url`, `endpoint`, `host`, `webhook`, `src`, … |
| Open Redirect | 🟡 MEDIUM | `redirect`, `return`, `next`, `back`, `goto`, … |
| SSTI | 🔴 CRITICAL | `template`, `theme`, `layout`, `render`, … |
| XXE | 🟠 HIGH | XML-type params, values containing `<?xml` |
| LDAP Injection | 🟠 HIGH | `username`, `uid`, `cn`, `member`, `group`, … |
| IDOR | 🟠 HIGH | `id`, `user_id`, `order_id` with numeric/UUID values |
| LFI / RFI | 🔴 CRITICAL | `file`, `include`, `lang`, `page`, `module`, … |
| HTTP Header Injection | 🟡 MEDIUM | `useragent`, `x_forwarded_for`, `referer`, … |

---

## Project structure

```
src/main/java/com/burpai/
├── BurpAISuggester.java          Extension entry point (implements BurpExtension)
├── AttackSuggester.java          Built-in rule engine
├── AiApiClient.java              OpenAI Chat API client
├── model/
│   ├── AttackType.java           Enum of attack types with payloads
│   ├── AttackSuggestion.java     Single suggestion (name, risk, description, payloads)
│   └── ParameterAnalysis.java    Result for one parameter
├── ui/
│   ├── MainPanel.java            Root suite-tab panel
│   ├── AnalyzerPanel.java        Analyzer sub-tab (table + detail)
│   └── SettingsPanel.java        Settings sub-tab (API key, model)
└── handler/
    └── AttackContextMenuProvider.java  Right-click context menu
```

---

## License

MIT
