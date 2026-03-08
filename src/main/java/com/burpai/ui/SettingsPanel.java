package com.burpai.ui;

import burp.api.montoya.MontoyaApi;
import com.burpai.AiApiClient;
import com.burpai.LlmConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Settings panel displayed in the "Settings" sub-tab of the AI Suggester suite tab.
 *
 * <p>Allows the user to configure:
 * <ul>
 *   <li>Analysis mode: built-in rules only vs. Ollama (local LLM)</li>
 *   <li>Ollama host / IP  (default: localhost – can point to another machine)</li>
 *   <li>Ollama port       (default: 11434)</li>
 *   <li>Model name        (free-text editable, popular Ollama models pre-filled)</li>
 *   <li>System prompt     (multi-line, fully editable)</li>
 * </ul>
 */
public class SettingsPanel extends JPanel {

    /** Common Ollama chat models shown as quick-select options. Embedding-only models are excluded. */
    private static final String[] OLLAMA_MODELS = {
            "llama3.2", "llama3.1", "llama3", "llama2",
            "mistral", "mistral-nemo",
            "codellama",
            "gemma2", "gemma",
            "phi3", "phi3.5",
            "qwen2.5", "qwen2",
            "deepseek-r1"
    };

    private final JRadioButton builtInRadio;
    private final JRadioButton ollamaRadio;
    private final JTextField   hostField;
    private final JTextField   portField;
    private final JComboBox<String> modelCombo;
    private final JTextArea    systemPromptArea;
    private final JLabel       statusLabel;

    public SettingsPanel(@SuppressWarnings("unused") MontoyaApi api) {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));

        // ----- Mode selection -----
        JPanel modePanel = createTitledPanel("Analysis Mode");
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.Y_AXIS));

        builtInRadio = new JRadioButton("Built-in rules only  (offline, no LLM required)");
        ollamaRadio  = new JRadioButton("Ollama  (local LLM – configurable host, port & model)");
        builtInRadio.setSelected(true);

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(builtInRadio);
        modeGroup.add(ollamaRadio);

        modePanel.add(builtInRadio);
        modePanel.add(Box.createVerticalStrut(4));
        modePanel.add(ollamaRadio);

        // ----- Ollama connection settings -----
        JPanel ollamaPanel = createTitledPanel("Ollama Configuration");
        ollamaPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets  = new Insets(4, 4, 4, 4);
        gbc.anchor  = GridBagConstraints.WEST;
        gbc.fill    = GridBagConstraints.HORIZONTAL;

        // Host row
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        ollamaPanel.add(new JLabel("Host / IP:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        hostField = new JTextField(LlmConfig.DEFAULT_HOST, 25);
        hostField.setToolTipText("Hostname or IP address of the machine running Ollama (e.g. 192.168.1.10)");
        ollamaPanel.add(hostField, gbc);

        // Port row
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        ollamaPanel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        portField = new JTextField(String.valueOf(LlmConfig.DEFAULT_PORT), 8);
        portField.setToolTipText("Ollama port (default: 11434)");
        ollamaPanel.add(portField, gbc);

        // Model row – editable combo so users can type any model name
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        ollamaPanel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        modelCombo = new JComboBox<>(OLLAMA_MODELS);
        modelCombo.setEditable(true);
        modelCombo.setSelectedItem(LlmConfig.DEFAULT_MODEL);
        modelCombo.setToolTipText("Ollama model name (e.g. llama3.2, mistral). Type a custom name if not listed.");
        ollamaPanel.add(modelCombo, gbc);

        // Endpoint preview label
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JLabel endpointLabel = new JLabel(" ");
        endpointLabel.setFont(endpointLabel.getFont().deriveFont(Font.ITALIC, 11f));
        endpointLabel.setForeground(Color.GRAY);
        ollamaPanel.add(endpointLabel, gbc);
        gbc.gridwidth = 1;

        // Buttons row
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.weightx = 0;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JButton saveBtn = new JButton("Save");
        JButton testBtn = new JButton("Test Connection");
        btnPanel.add(saveBtn);
        btnPanel.add(Box.createHorizontalStrut(8));
        btnPanel.add(testBtn);
        ollamaPanel.add(btnPanel, gbc);

        // Status label
        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC));

        // ----- System prompt panel -----
        JPanel promptPanel = createTitledPanel("System Prompt  (sent to the LLM before each analysis)");
        promptPanel.setLayout(new BorderLayout(4, 4));

        systemPromptArea = new JTextArea(LlmConfig.DEFAULT_SYSTEM_PROMPT, 8, 60);
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        systemPromptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane promptScroll = new JScrollPane(systemPromptArea);

        JButton resetPromptBtn = new JButton("Reset to Default");
        resetPromptBtn.addActionListener(e -> systemPromptArea.setText(LlmConfig.DEFAULT_SYSTEM_PROMPT));

        JPanel promptBtnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        promptBtnPanel.add(resetPromptBtn);

        promptPanel.add(promptScroll, BorderLayout.CENTER);
        promptPanel.add(promptBtnPanel, BorderLayout.SOUTH);

        // ----- Info panel -----
        JPanel infoPanel = createTitledPanel("How to Use");
        infoPanel.setLayout(new BorderLayout());
        JTextArea info = new JTextArea(
                "1. Right-click any HTTP request in Proxy, Repeater, Target, or Intruder.\n"
                + "2. Select \"AI Suggester: Analyze Request\".\n"
                + "3. Switch to the \"Analyzer\" tab to see per-parameter attack suggestions.\n\n"
                + "Built-in rules work entirely offline. Ollama mode sends each parameter to\n"
                + "your local Ollama instance for richer, context-aware suggestions.\n"
                + "Make sure Ollama is running and the model is pulled (ollama pull <model>)."
        );
        info.setEditable(false);
        info.setBackground(infoPanel.getBackground());
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        info.setMargin(new Insets(4, 4, 4, 4));
        infoPanel.add(info, BorderLayout.CENTER);

        // ----- Assemble -----
        inner.add(modePanel);
        inner.add(Box.createVerticalStrut(8));
        inner.add(ollamaPanel);
        inner.add(Box.createVerticalStrut(4));
        inner.add(statusLabel);
        inner.add(Box.createVerticalStrut(8));
        inner.add(promptPanel);
        inner.add(Box.createVerticalStrut(8));
        inner.add(infoPanel);

        add(inner, BorderLayout.NORTH);

        // ----- Wire listeners -----
        builtInRadio.addActionListener(e -> updateOllamaPanelState(ollamaPanel, promptPanel));
        ollamaRadio.addActionListener(e -> updateOllamaPanelState(ollamaPanel, promptPanel));
        updateOllamaPanelState(ollamaPanel, promptPanel);

        // Live endpoint preview – single shared listener reused for both fields
        Runnable refreshEndpoint = () ->
                endpointLabel.setText("→  http://" + hostField.getText().trim()
                        + ":" + portField.getText().trim() + "/v1/chat/completions");
        javax.swing.event.DocumentListener endpointRefresher = new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e)  { refreshEndpoint.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e)  { refreshEndpoint.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { refreshEndpoint.run(); }
        };
        hostField.getDocument().addDocumentListener(endpointRefresher);
        portField.getDocument().addDocumentListener(endpointRefresher);
        refreshEndpoint.run();

        saveBtn.addActionListener(e -> {
            if (validateFields()) {
                showStatus("Settings saved.", new Color(0, 128, 0));
            }
        });

        testBtn.addActionListener(e -> testConnection(testBtn));
    }

    // -----------------------------------------------------------------------
    // Accessors used by MainPanel
    // -----------------------------------------------------------------------

    /** Returns true when Ollama mode is selected. */
    public boolean isUseAi() { return ollamaRadio.isSelected(); }

    /**
     * Builds and returns an {@link LlmConfig} from the current UI values.
     * Returns {@code null} if built-in-only mode is selected or fields are invalid.
     */
    public LlmConfig getLlmConfig() {
        if (!ollamaRadio.isSelected()) return null;
        try {
            String host      = hostField.getText().trim();
            int    port      = Integer.parseInt(portField.getText().trim());
            String model     = getSelectedModel();
            if (model.isEmpty()) model = LlmConfig.DEFAULT_MODEL;
            String sysPrompt = systemPromptArea.getText().trim();
            if (sysPrompt.isEmpty()) sysPrompt = LlmConfig.DEFAULT_SYSTEM_PROMPT;
            return new LlmConfig(host, port, model, sysPrompt, "", LlmConfig.DEFAULT_TIMEOUT);
        } catch (Exception e) {
            return null;
        }
    }

    /** Returns the currently selected/typed model name. */
    public String getSelectedModel() {
        Object item = modelCombo.getSelectedItem();
        return item != null ? item.toString().trim() : LlmConfig.DEFAULT_MODEL;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private void updateOllamaPanelState(JPanel ollamaPanel, JPanel promptPanel) {
        boolean enabled = ollamaRadio.isSelected();
        setChildrenEnabled(ollamaPanel, enabled);
        setChildrenEnabled(promptPanel, enabled);
    }

    private void setChildrenEnabled(Container container, boolean enabled) {
        for (Component c : container.getComponents()) {
            c.setEnabled(enabled);
            if (c instanceof Container con) setChildrenEnabled(con, enabled);
        }
    }

    private boolean validateFields() {
        String host = hostField.getText().trim();
        if (host.isEmpty()) { showStatus("Host cannot be empty.", Color.RED); return false; }
        try {
            int port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            showStatus("Port must be a number between 1 and 65535.", Color.RED);
            return false;
        }
        if (getSelectedModel().isEmpty()) { showStatus("Model cannot be empty.", Color.RED); return false; }
        return true;
    }

    private void testConnection(JButton testBtn) {
        if (!validateFields()) return;
        LlmConfig config = getLlmConfig();
        if (config == null) { showStatus("Please select Ollama mode and fill in all fields.", Color.RED); return; }

        testBtn.setEnabled(false);
        showStatus("Testing connection to " + config.endpointUrl() + " …", Color.GRAY);

        new Thread(() -> {
            try {
                AiApiClient.getSuggestions("https://example.com/", "GET",
                        "test", "1", "URL", config);
                SwingUtilities.invokeLater(() ->
                        showStatus("✔ Connected to Ollama (" + config.model() + ")", new Color(0, 128, 0)));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        showStatus("✘ Connection failed: " + ex.getMessage(), Color.RED));
            } finally {
                SwingUtilities.invokeLater(() -> testBtn.setEnabled(true));
            }
        }, "ollama-test-thread").start();
    }

    private void showStatus(String msg, Color colour) {
        statusLabel.setText(msg);
        statusLabel.setForeground(colour);
    }

    private JPanel createTitledPanel(String title) {
        JPanel panel = new JPanel();
        TitledBorder border = BorderFactory.createTitledBorder(title);
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD));
        panel.setBorder(BorderFactory.createCompoundBorder(
                border,
                BorderFactory.createEmptyBorder(4, 8, 8, 8)));
        return panel;
    }
}
