package com.burpai;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.burpai.handler.AttackContextMenuProvider;
import com.burpai.ui.MainPanel;

/**
 * Entry point for the Burp Suite "AI Attack Suggester" extension.
 *
 * <p>Registered capabilities:
 * <ul>
 *   <li>A suite tab ("AI Suggester") showing the request analyzer and settings.</li>
 *   <li>A context menu item in every Burp tool that presents HTTP requests,
 *       allowing users to send a request for analysis with a single click.</li>
 * </ul>
 */
public class BurpAISuggester implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AI Attack Suggester");

        api.logging().logToOutput(
                "AI Attack Suggester v1.0 loaded.\n"
                + "Right-click any HTTP request and select \"AI Suggester: Analyze Request\" to begin."
        );

        // Build the main UI panel (must be created on the EDT for Swing safety,
        // but Burp calls initialize() on the Swing EDT so this is fine).
        MainPanel mainPanel = new MainPanel(api);

        // Register the suite tab – appears as "AI Suggester" in the Burp toolbar.
        api.userInterface().registerSuiteTab("AI Suggester", mainPanel);

        // Register the context menu provider – adds a menu item when right-clicking
        // requests in Proxy, Repeater, Target, Intruder, etc.
        api.userInterface().registerContextMenuItemsProvider(
                new AttackContextMenuProvider(mainPanel));
    }
}
