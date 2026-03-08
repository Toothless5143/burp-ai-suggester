package com.burpai.handler;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.burpai.ui.MainPanel;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Provides a right-click context menu item in any Burp tool that shows HTTP requests
 * (Proxy history, Repeater, Target, Intruder, …).
 *
 * <p>Clicking "Analyze with AI Suggester" sends the selected request to the
 * {@link MainPanel} and switches to the AI Suggester suite tab.
 */
public class AttackContextMenuProvider implements ContextMenuItemsProvider {

    private final MainPanel mainPanel;

    public AttackContextMenuProvider(MainPanel mainPanel) {
        this.mainPanel = mainPanel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Try to extract a single HttpRequest from the event
        Optional<HttpRequest> requestOpt = extractRequest(event);
        if (requestOpt.isEmpty()) return items;

        HttpRequest request = requestOpt.get();

        JMenuItem analyzeItem = new JMenuItem("AI Suggester: Analyze Request");
        analyzeItem.addActionListener(e -> SwingUtilities.invokeLater(() ->
                mainPanel.analyzeRequest(request)));

        items.add(analyzeItem);
        return items;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private Optional<HttpRequest> extractRequest(ContextMenuEvent event) {
        // 1. Message editor context (Repeater, Proxy request view, etc.)
        Optional<MessageEditorHttpRequestResponse> editorCtx = event.messageEditorRequestResponse();
        if (editorCtx.isPresent()) {
            HttpRequestResponse rr = editorCtx.get().requestResponse();
            if (rr != null && rr.request() != null) {
                return Optional.of(rr.request());
            }
        }

        // 2. Selected rows in Proxy history / Target site map
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (!selected.isEmpty()) {
            HttpRequestResponse rr = selected.get(0);
            if (rr != null && rr.request() != null) {
                return Optional.of(rr.request());
            }
        }

        return Optional.empty();
    }
}
