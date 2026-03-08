package com.burpai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.burpai.AttackSuggester;
import com.burpai.model.AttackSuggestion;
import com.burpai.model.ParameterAnalysis;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * The "Analyzer" sub-tab of the AI Suggester suite tab.
 *
 * <p>Layout (top → bottom):
 * <ol>
 *   <li>Request summary bar (URL, method, parameter count) + "Analyze" / "Clear" buttons.</li>
 *   <li>Split pane – left: parameter table; right: attack detail pane.</li>
 *   <li>Status bar.</li>
 * </ol>
 */
public class AnalyzerPanel extends JPanel {

    private final MontoyaApi         api;
    private final AttackSuggester    suggester = new AttackSuggester();
    private final MainPanel          mainPanel;

    // UI components
    private final JLabel             requestLabel;
    private final JButton            analyzeButton;
    private final JButton            clearButton;
    private final JLabel             statusLabel;
    private final ParameterTableModel tableModel;
    private final JTable             paramTable;
    private final JEditorPane        detailPane;

    // State
    private HttpRequest              currentRequest;
    private List<ParameterAnalysis>  currentResults = new ArrayList<>();

    public AnalyzerPanel(MontoyaApi api, MainPanel mainPanel) {
        this.api       = api;
        this.mainPanel = mainPanel;
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ----- Top toolbar -----
        JPanel toolbar = new JPanel(new BorderLayout(8, 4));

        requestLabel = new JLabel("No request loaded. Right-click any request and choose \"AI Suggester: Analyze Request\".");
        requestLabel.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        analyzeButton = new JButton("⚡ Analyze");
        clearButton   = new JButton("Clear");
        analyzeButton.setEnabled(false);
        clearButton.setEnabled(false);
        analyzeButton.setToolTipText("Run attack analysis on the loaded request");
        clearButton.setToolTipText("Clear the current analysis");
        btnPanel.add(analyzeButton);
        btnPanel.add(clearButton);

        toolbar.add(requestLabel, BorderLayout.CENTER);
        toolbar.add(btnPanel, BorderLayout.EAST);

        // ----- Parameter table (left side of split) -----
        tableModel = new ParameterTableModel();
        paramTable = new JTable(tableModel);
        paramTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        paramTable.setRowHeight(22);
        paramTable.getTableHeader().setReorderingAllowed(false);
        paramTable.setFillsViewportHeight(true);

        // Column widths
        paramTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        paramTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        paramTable.getColumnModel().getColumn(2).setPreferredWidth(120);
        paramTable.getColumnModel().getColumn(3).setPreferredWidth(320);

        // Colour the "Risk" column
        paramTable.getColumnModel().getColumn(2).setCellRenderer(new RiskCellRenderer());

        JScrollPane tableScroll = new JScrollPane(paramTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Parameters"));

        // ----- Detail pane (right side of split) -----
        detailPane = new JEditorPane("text/html", buildWelcomeHtml());
        detailPane.setEditable(false);
        detailPane.setBackground(UIManager.getColor("Panel.background"));
        JScrollPane detailScroll = new JScrollPane(detailPane);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Attack Suggestions"));

        // ----- Split pane -----
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detailScroll);
        split.setResizeWeight(0.30);
        split.setDividerLocation(320);

        // ----- Status bar -----
        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

        // ----- Assemble -----
        add(toolbar, BorderLayout.NORTH);
        add(split,   BorderLayout.CENTER);
        add(statusLabel, BorderLayout.SOUTH);

        // ----- Wire up listeners -----
        analyzeButton.addActionListener(e -> runAnalysis());
        clearButton.addActionListener(e -> clearAnalysis());

        paramTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = paramTable.getSelectedRow();
                if (row >= 0 && row < currentResults.size()) {
                    showDetail(currentResults.get(row));
                }
            }
        });

        // Double-click to copy parameter name
        paramTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = paramTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        String name = (String) tableModel.getValueAt(row, 0);
                        Toolkit.getDefaultToolkit().getSystemClipboard()
                                .setContents(new java.awt.datatransfer.StringSelection(name), null);
                        setStatus("Parameter name \"" + name + "\" copied to clipboard.");
                    }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Public API called by MainPanel / context menu
    // -----------------------------------------------------------------------

    /**
     * Loads the given request into the analyzer and triggers automatic analysis.
     * Safe to call from any thread.
     */
    public void analyzeRequest(HttpRequest request) {
        SwingUtilities.invokeLater(() -> {
            currentRequest = request;
            String display = request.method() + "  " + request.url();
            if (display.length() > 100) display = display.substring(0, 97) + "…";
            requestLabel.setText(display);
            analyzeButton.setEnabled(true);
            clearButton.setEnabled(true);
            runAnalysis();
        });
    }

    // -----------------------------------------------------------------------
    // Internal actions
    // -----------------------------------------------------------------------

    private void runAnalysis() {
        if (currentRequest == null) return;

        analyzeButton.setEnabled(false);
        tableModel.setData(new ArrayList<>());
        detailPane.setText(buildSpinnerHtml());
        setStatus("Analyzing " + currentRequest.parameters().size() + " parameter(s)…");

        String apiKey = mainPanel.getApiKey();
        String model  = mainPanel.getSelectedModel();
        boolean useAi = mainPanel.isUseAi() && !apiKey.isEmpty();

        SwingWorker<List<ParameterAnalysis>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<ParameterAnalysis> doInBackground() {
                return suggester.analyze(currentRequest, useAi ? apiKey : null, model);
            }

            @Override
            protected void done() {
                try {
                    currentResults = get();
                    tableModel.setData(currentResults);

                    if (currentResults.isEmpty()) {
                        detailPane.setText(buildNoParamsHtml());
                        setStatus("No parameters detected in this request.");
                    } else {
                        // Auto-select first row
                        paramTable.setRowSelectionInterval(0, 0);
                        showDetail(currentResults.get(0));
                        long total = currentResults.stream()
                                .mapToLong(r -> r.getSuggestions().size()).sum();
                        String src = useAi ? "AI-enhanced" : "built-in rules";
                        setStatus("Analysis complete (" + src + "): "
                                + currentResults.size() + " parameter(s), "
                                + total + " suggestion(s) found.");
                    }
                } catch (Exception ex) {
                    setStatus("Analysis failed: " + ex.getMessage());
                    detailPane.setText(buildErrorHtml(ex.getMessage()));
                } finally {
                    analyzeButton.setEnabled(true);
                }
            }
        };
        worker.execute();
    }

    private void clearAnalysis() {
        currentRequest = null;
        currentResults  = new ArrayList<>();
        tableModel.setData(currentResults);
        requestLabel.setText("No request loaded. Right-click any request and choose \"AI Suggester: Analyze Request\".");
        detailPane.setText(buildWelcomeHtml());
        analyzeButton.setEnabled(false);
        clearButton.setEnabled(false);
        setStatus(" ");
    }

    private void showDetail(ParameterAnalysis analysis) {
        detailPane.setText(buildDetailHtml(analysis));
        detailPane.setCaretPosition(0);
    }

    private void setStatus(String msg) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(msg));
    }

    // -----------------------------------------------------------------------
    // HTML builders
    // -----------------------------------------------------------------------

    private String buildWelcomeHtml() {
        return "<html><body style='font-family:sans-serif; margin:16px;'>"
                + "<h2 style='color:#555;'>AI Attack Suggester</h2>"
                + "<p>To get started:</p>"
                + "<ol>"
                + "<li>Right-click any HTTP request in <b>Proxy</b>, <b>Repeater</b>, "
                + "<b>Target</b>, or <b>Intruder</b>.</li>"
                + "<li>Select <b>AI Suggester: Analyze Request</b>.</li>"
                + "<li>Select a parameter in the table on the left to see attack suggestions.</li>"
                + "</ol>"
                + "<p style='color:#888; font-size:0.9em;'>Configure AI mode in the <b>Settings</b> tab.</p>"
                + "</body></html>";
    }

    private String buildSpinnerHtml() {
        return "<html><body style='font-family:sans-serif; margin:16px;'>"
                + "<p>Analyzing parameters…</p>"
                + "</body></html>";
    }

    private String buildNoParamsHtml() {
        return "<html><body style='font-family:sans-serif; margin:16px;'>"
                + "<p>No parameters were detected in this request.</p>"
                + "</body></html>";
    }

    private String buildErrorHtml(String msg) {
        return "<html><body style='font-family:sans-serif; margin:16px;'>"
                + "<p style='color:red;'>Error: " + escapeHtml(msg) + "</p>"
                + "</body></html>";
    }

    private String buildDetailHtml(ParameterAnalysis analysis) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:sans-serif; margin:16px;'>");
        sb.append("<h2 style='margin-bottom:2px;'>")
          .append(escapeHtml(analysis.getParamName()))
          .append("</h2>");
        sb.append("<p style='color:#666; margin-top:0;'>")
          .append(analysis.getParamType()).append(" parameter")
          .append(" &nbsp;|&nbsp; Value: <code>")
          .append(escapeHtml(truncate(analysis.getParamValue(), 80)))
          .append("</code></p>");

        if (analysis.getSuggestions().isEmpty()) {
            sb.append("<p style='color:#888;'>No attack vectors identified for this parameter.</p>");
        } else {
            for (AttackSuggestion suggestion : analysis.getSuggestions()) {
                String colour = suggestion.getRiskColour();
                String emoji  = suggestion.getRiskEmoji();

                sb.append("<div style='margin-bottom:16px; padding:10px; "
                        + "border-left:4px solid ").append(colour).append(";'>");

                sb.append("<h3 style='margin:0 0 4px 0; color:").append(colour).append(";'>")
                  .append(emoji).append(" ").append(escapeHtml(suggestion.getAttackName()))
                  .append(" <span style='font-size:0.8em; font-weight:normal;'>[")
                  .append(suggestion.getRiskLevel()).append("]</span>");
                if (suggestion.isFromAi()) {
                    sb.append(" <span style='font-size:0.75em; color:#0066cc;'>✨ AI</span>");
                }
                sb.append("</h3>");

                sb.append("<p style='margin:4px 0 8px 0;'>")
                  .append(escapeHtml(suggestion.getDescription()))
                  .append("</p>");

                if (!suggestion.getPayloads().isEmpty()) {
                    sb.append("<b>Sample payloads / techniques:</b><ul style='margin:4px 0;'>");
                    for (String payload : suggestion.getPayloads()) {
                        sb.append("<li><code style='background:#f4f4f4; padding:1px 4px;'>")
                          .append(escapeHtml(payload))
                          .append("</code></li>");
                    }
                    sb.append("</ul>");
                }

                sb.append("</div>");
            }
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    // -----------------------------------------------------------------------
    // Table model
    // -----------------------------------------------------------------------

    private static class ParameterTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Parameter", "Type", "Risk", "Suggested Attacks"};
        private List<ParameterAnalysis> data = new ArrayList<>();

        void setData(List<ParameterAnalysis> data) {
            this.data = data;
            fireTableDataChanged();
        }

        @Override public int getRowCount()    { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int col) { return COLUMNS[col]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override
        public Object getValueAt(int row, int col) {
            ParameterAnalysis pa = data.get(row);
            return switch (col) {
                case 0 -> pa.getParamName();
                case 1 -> pa.getParamType();
                case 2 -> pa.getHighestRisk();
                case 3 -> pa.getSuggestionsLabel();
                default -> "";
            };
        }
    }

    // -----------------------------------------------------------------------
    // Risk cell renderer
    // -----------------------------------------------------------------------

    private static class RiskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                String risk = value == null ? "" : value.toString();
                switch (risk) {
                    case "CRITICAL" -> setForeground(new Color(155, 0, 0));
                    case "HIGH"     -> setForeground(new Color(204, 51, 0));
                    case "MEDIUM"   -> setForeground(new Color(230, 126, 0));
                    default         -> setForeground(UIManager.getColor("Table.foreground"));
                }
            } else {
                setForeground(UIManager.getColor("Table.selectionForeground"));
            }
            return this;
        }
    }
}
