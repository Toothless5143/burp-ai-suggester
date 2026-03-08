package com.burpai.ui;

import burp.api.montoya.MontoyaApi;
import com.burpai.AiApiClient;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Settings panel displayed in the "Settings" sub-tab of the AI Suggester suite tab.
 *
 * <p>Allows the user to configure:
 * <ul>
 *   <li>Analysis mode: built-in rules only vs. AI-enhanced (OpenAI API)</li>
 *   <li>OpenAI API key</li>
 *   <li>OpenAI model selection</li>
 * </ul>
 */
public class SettingsPanel extends JPanel {

    private static final String[] MODELS = {
            "gpt-4o", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"
    };

    private final JRadioButton builtInRadio;
    private final JRadioButton aiRadio;
    private final JPasswordField apiKeyField;
    private final JComboBox<String> modelCombo;
    private final JLabel statusLabel;

    public SettingsPanel(@SuppressWarnings("unused") MontoyaApi api) {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));

        // ----- Mode selection -----
        JPanel modePanel = createTitledPanel("Analysis Mode");
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.Y_AXIS));

        builtInRadio = new JRadioButton("Built-in rules only  (no internet connection required)");
        aiRadio      = new JRadioButton("AI-enhanced  (requires OpenAI API key)");
        builtInRadio.setSelected(true);

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(builtInRadio);
        modeGroup.add(aiRadio);

        modePanel.add(builtInRadio);
        modePanel.add(Box.createVerticalStrut(4));
        modePanel.add(aiRadio);

        // ----- OpenAI settings -----
        JPanel aiPanel = createTitledPanel("OpenAI Configuration");
        aiPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets  = new Insets(4, 4, 4, 4);
        gbc.anchor  = GridBagConstraints.WEST;
        gbc.fill    = GridBagConstraints.HORIZONTAL;

        // API key row
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        aiPanel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(40);
        apiKeyField.setToolTipText("Your OpenAI API key (sk-…)");
        aiPanel.add(apiKeyField, gbc);

        // Model row
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        aiPanel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        modelCombo = new JComboBox<>(MODELS);
        modelCombo.setSelectedItem("gpt-4o");
        aiPanel.add(modelCombo, gbc);

        // Buttons row
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 0;
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JButton saveBtn = new JButton("Save");
        JButton testBtn = new JButton("Test Connection");
        btnPanel.add(saveBtn);
        btnPanel.add(Box.createHorizontalStrut(8));
        btnPanel.add(testBtn);
        aiPanel.add(btnPanel, gbc);

        // Status label
        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC));

        // ----- Info panel -----
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("How to Use"));
        JTextArea info = new JTextArea(
                "1. Right-click any HTTP request in Proxy, Repeater, Target, or Intruder.\n"
                + "2. Select \"AI Suggester: Analyze Request\".\n"
                + "3. Switch to the \"Analyzer\" tab to see per-parameter attack suggestions.\n\n"
                + "The built-in rules work offline and require no configuration.\n"
                + "Enable AI mode to get richer, context-aware suggestions via the OpenAI API.\n"
                + "Your API key is stored in memory only and is not persisted between sessions."
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
        inner.add(aiPanel);
        inner.add(Box.createVerticalStrut(4));
        inner.add(statusLabel);
        inner.add(Box.createVerticalStrut(8));
        inner.add(infoPanel);

        add(inner, BorderLayout.NORTH);

        // ----- Wire listeners -----
        builtInRadio.addActionListener(e -> updateAiPanelState(aiPanel));
        aiRadio.addActionListener(e -> updateAiPanelState(aiPanel));
        updateAiPanelState(aiPanel);

        saveBtn.addActionListener(e -> {
            statusLabel.setForeground(new Color(0, 128, 0));
            statusLabel.setText("Settings saved.");
        });

        testBtn.addActionListener(e -> testConnection(testBtn));
    }

    // -----------------------------------------------------------------------
    // Accessors used by the parent panel
    // -----------------------------------------------------------------------

    public boolean isUseAi() { return aiRadio.isSelected(); }

    public String getApiKey() { return new String(apiKeyField.getPassword()).trim(); }

    public String getSelectedModel() {
        Object item = modelCombo.getSelectedItem();
        return item != null ? item.toString() : "gpt-4o";
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private void updateAiPanelState(JPanel aiPanel) {
        boolean enabled = aiRadio.isSelected();
        setChildrenEnabled(aiPanel, enabled);
    }

    private void setChildrenEnabled(Container container, boolean enabled) {
        for (Component c : container.getComponents()) {
            c.setEnabled(enabled);
            if (c instanceof Container con) setChildrenEnabled(con, enabled);
        }
    }

    private void testConnection(JButton testBtn) {
        String key = getApiKey();
        if (key.isEmpty()) {
            showStatus("Please enter an API key.", Color.RED);
            return;
        }
        testBtn.setEnabled(false);
        showStatus("Testing connection…", Color.GRAY);

        new Thread(() -> {
            try {
                // Minimal API call to verify the key (expects a well-formed JSON back)
                AiApiClient.getSuggestions("https://example.com/", "GET",
                        "test", "1", "URL", key, getSelectedModel());
                SwingUtilities.invokeLater(() ->
                        showStatus("✔ Connection successful!", new Color(0, 128, 0)));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        showStatus("✘ Connection failed: " + ex.getMessage(), Color.RED));
            } finally {
                SwingUtilities.invokeLater(() -> testBtn.setEnabled(true));
            }
        }, "ai-test-thread").start();
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
