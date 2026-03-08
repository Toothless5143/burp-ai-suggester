package com.burpai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.burpai.LlmConfig;

import javax.swing.*;
import java.awt.*;

/**
 * Root panel registered as the "AI Suggester" Burp Suite tab.
 *
 * <p>Contains two sub-tabs:
 * <ul>
 *   <li><b>Analyzer</b> – displays the request under analysis and per-parameter
 *       attack suggestions.</li>
 *   <li><b>Settings</b> – lets the user configure analysis mode, Ollama host/port,
 *       model, and system prompt.</li>
 * </ul>
 *
 * <p>The context menu provider and any other component that needs to trigger
 * analysis calls {@link #analyzeRequest(HttpRequest)} on this panel.
 */
public class MainPanel extends JPanel {

    private final SettingsPanel settingsPanel;
    private final AnalyzerPanel analyzerPanel;
    private final JTabbedPane   tabs;

    public MainPanel(MontoyaApi api) {
        setLayout(new BorderLayout());

        settingsPanel = new SettingsPanel(api);
        analyzerPanel = new AnalyzerPanel(api, this);

        tabs = new JTabbedPane();
        tabs.addTab("Analyzer", analyzerPanel);
        tabs.addTab("Settings", settingsPanel);

        add(tabs, BorderLayout.CENTER);
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Sends the given request to the analyzer and switches to the Analyzer tab.
     * Safe to call from any thread.
     */
    public void analyzeRequest(HttpRequest request) {
        analyzerPanel.analyzeRequest(request);
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(0));
    }

    /**
     * Returns a fully populated {@link LlmConfig} when Ollama mode is active,
     * or {@code null} when built-in-rules-only mode is selected.
     */
    public LlmConfig getLlmConfig() { return settingsPanel.getLlmConfig(); }

    /** Returns true if Ollama mode is selected in settings. */
    public boolean isUseAi() { return settingsPanel.isUseAi(); }
}
