package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedList;
import java.util.List;


public class BurpExtender implements BurpExtension, IBurpExtender, IContextMenuFactory, ITab {
	
	
    public static final String VERSION = "2.4.2";
    private static final String EXTENSION_NAME = "ATOR v" + VERSION;
    private static final String EXTENSION_NAME_TAB_NAME = EXTENSION_NAME;
    public static SpotErrorMetaData spoterroMetaData = null;;
    public static IBurpExtenderCallbacks callbacks;
    public static MontoyaApi api;
	public static String bodyContentType;
    IExtensionHelpers helpers;
    JTabbedPane atorconfigurationPane, mainTabbedPane;
    JPanel errorPanel, tokenObtainPanel, replacePanel, previewPanel;
    BurpExtender burpextender;
    private static boolean handlersRegistered;
    private static boolean readyLogged;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        api.extension().setName(EXTENSION_NAME);
        DomainFilter.ensureLoaded();
        registerMontoyaHandlers();
        logReady();
    }
   
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callbacks = iBurpExtenderCallbacks;
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerContextMenuFactory(this);
        callbacks.addSuiteTab(this);
        DomainFilter.ensureLoaded();
        registerMontoyaHandlers();
        logReady();
     }

    private static void registerMontoyaHandlers() {
        if (handlersRegistered || api == null) {
            return;
        }
        handlersRegistered = true;
        api.http().registerHttpHandler(new AtorHttpHandler());
        api.http().registerSessionHandlingAction(new AtorSessionAction());
    }

    public static void log(String message) {
        if (callbacks != null) {
            callbacks.printOutput(message);
            return;
        }
        if (api != null) {
            api.logging().logToOutput(message);
        }
    }

    private static void logReady() {
        if (readyLogged || api == null || callbacks == null) {
            return;
        }
        readyLogged = true;
        log("ATOR v" + VERSION + " loaded for Burp 2026.8 (Montoya HTTP handler, HTTP/2 safe).");
        log("Session handling action name: " + AtorSessionAction.NAME);
        log(DomainFilter.statusText() + " Settings, Send to ATOR > Add domain, or " + AtorHttpHandler.COMMAND_HEADER + ": domains.");
        log("burp-mcp send_http1_request and send_http2_request are handled when Extensions is enabled.");
        log("burp-mcp commands use header " + AtorHttpHandler.COMMAND_HEADER
                + ": status, refresh, export, import, domains. Accepted from Extensions, Burp AI, and Repeater. The request is not sent.");
        log("import: HTTP body is an ATOR export JSON document. export returns that document.");
    }

	public BurpExtender getComponent() {
		return BurpExtender.this;
	}

	@Override
	public String getTabCaption() {
		return EXTENSION_NAME_TAB_NAME;
	}


	@Override
	public Component getUiComponent() {
		mainTabbedPane = new JTabbedPane();
		atorconfigurationPane = new JTabbedPane();
		SetttingsTab setttingsTab = new SetttingsTab(callbacks);
		
		panelCreation();
		
		mainTabbedPane.add("ATOR Configuration", atorconfigurationPane);
		mainTabbedPane.add("Settings", setttingsTab.initSettingsGui());
		return mainTabbedPane;
	}

	private void panelCreation() {
		/**
		 * Panel for Error Condition, Obtain Token, Error Condition Replacement and Preview.
		 * 
		 */
		errorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		tokenObtainPanel = new JPanel();
		replacePanel = new JPanel();
		previewPanel = new JPanel();
		
		
		atorconfigurationPane.add("1. Error Condition >>>", errorPanel);
		atorconfigurationPane.add("2. Obtain Token >>>", tokenObtainPanel);
		atorconfigurationPane.add("3. Error Condition Replacement >>>", replacePanel);
		atorconfigurationPane.add("4. Preview >>>", previewPanel);
		
		
		JPanel errorPanelInst = new ErrorPanel(callbacks, getComponent()).preparePanel();
		JScrollPane jScrollerrorPane = new JScrollPane(errorPanelInst, 
        		ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
        		ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        		);
		
		errorPanel.setLayout(new BorderLayout());
		errorPanel.add(jScrollerrorPane, BorderLayout.CENTER);
		
		JPanel obtainPanel = new ObtainPanel(callbacks, getComponent()).preparePanel();
		JScrollPane jScrollPane = new JScrollPane(obtainPanel, 
        		ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
        		ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        		);
		
		tokenObtainPanel.setLayout(new BorderLayout());
		tokenObtainPanel.add(jScrollPane, BorderLayout.CENTER);
		
		
		JPanel replacementPanel = new ReplacePanel(callbacks, getComponent()).preparePanel();
		JScrollPane jScrollreplacementPane = new JScrollPane(replacementPanel, 
        		ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
        		ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        		);
		
		replacePanel.setLayout(new BorderLayout());
		replacePanel.add(jScrollreplacementPane, BorderLayout.CENTER);

		
		JPanel previewscrollPanel = new PreviewPanel(callbacks, getComponent()).preparePanel();
		JScrollPane jScrollpreviewPane = new JScrollPane(previewscrollPanel, 
        		ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
        		ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        		);
		
		previewPanel.setLayout(new BorderLayout());
		previewPanel.add(jScrollpreviewPane, BorderLayout.CENTER);
		
		
		customiseToBurp(errorPanel);
		customiseToBurp(tokenObtainPanel);
		customiseToBurp(replacePanel);
		customiseToBurp(previewPanel);
	}

	private void customiseToBurp(Component component) {
		callbacks.customizeUiComponent(component);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages.length > 0) {
			List<JMenuItem> menu = new LinkedList<>();
			JMenu mainmenu = new JMenu("Send to " + EXTENSION_NAME);
			JMenuItem errorMenu = new JMenuItem("1. Error Condition");
			JMenuItem atorMacroMenu = new JMenuItem("2. ATOR Macro (Obtain Token)");
			JMenuItem domainMenu = new JMenuItem("3. Add domain");
			errorMenu.addActionListener(new MenuAllListener(callbacks, messages, MenuActions.ATOR_ERROR, getComponent()));
			atorMacroMenu.addActionListener(new MenuAllListener(callbacks, messages, MenuActions.ATOR_MACRO, getComponent()));
			domainMenu.addActionListener(new MenuAllListener(callbacks, messages, MenuActions.ADD_DOMAIN, getComponent()));
			mainmenu.add(errorMenu);
			mainmenu.add(atorMacroMenu);
			mainmenu.add(domainMenu);
			
			menu.add(mainmenu);
            return menu;
		}
		return null;
	}
	
	
}