package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;

public class SetttingsTab {
	private static JCheckBox boxRepeater;
    private static JCheckBox boxIntruder;
    private static JCheckBox boxScanner;
    private static JCheckBox boxSequencer;
    private static JCheckBox boxSpider;
    private static JCheckBox boxProxy;
    private static JCheckBox boxExtender;
    private static JCheckBox boxBurpAi;
    public static JCheckBox inScope;
    private static final DefaultListModel<String> DOMAIN_MODEL = new DefaultListModel<>();
    private static JCheckBox onlyDomains;
    private static JTextField domainField;
    private static JLabel domainStatus;
    private static JLabel domainError;
    private static boolean domainListenerRegistered;
    static Color BURP_ORANGE = new Color(229, 137, 0);
    private Font headerFont = new Font("Nimbus", Font.BOLD, 13);
    private JButton exportATOR;
    private JButton importATOR;
    public static JLabel importATORFile;
    public static JLabel exportATORFile;
    
    IBurpExtenderCallbacks callbacks;
	public SetttingsTab(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}
	
	public JTabbedPane initSettingsGui(){
		
		JTabbedPane settingsTab = new JTabbedPane();
		
    	boxRepeater = new JCheckBox("Repeater", true);
        boxIntruder = new JCheckBox("Intruder", true);
        boxScanner = new JCheckBox("Scanner", true);
        boxSequencer = new JCheckBox("Sequencer", true);
        boxSpider = new JCheckBox("Spider", true);
        boxProxy = new JCheckBox("Proxy (browser)", true);
        boxExtender = new JCheckBox("Extensions (burp-mcp)", true);
        boxBurpAi = new JCheckBox("Burp AI", true);
        inScope = new JCheckBox("InScope", false);
        

        JLabel header1 = new JLabel("Tools scope");
        header1.setAlignmentX(Component.LEFT_ALIGNMENT);
        header1.setForeground(BURP_ORANGE);
        header1.setFont(headerFont);
        header1.setBorder(new EmptyBorder(5, 0, 5, 0));

        JLabel label2 = new JLabel("Select the tools ATOR updates. Extensions covers burp-mcp send_http1_request and send_http2_request.");
        label2.setAlignmentX(Component.LEFT_ALIGNMENT);
        label2.setBorder(new EmptyBorder(0, 0, 10, 0));

        JButton toggleScopesButton = new JButton("All/None");

        toggleScopesButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        toggleScopesButton.addActionListener(new MenuAllListener(callbacks, this, MenuActions.A_ENABLE_DISABLE));

        // Scope
        JPanel scopePanel = new JPanel();
        scopePanel.setBorder(new EmptyBorder(10, 0, 10, 0));

        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.LINE_AXIS));
        scopePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel col1 = new JPanel();
        col1.setLayout(new BoxLayout(col1, BoxLayout.PAGE_AXIS));
        col1.add(boxRepeater);
        col1.add(boxIntruder);
        col1.add(boxExtender);
        col1.add(boxBurpAi);
        col1.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel col2 = new JPanel();
        col2.setLayout(new BoxLayout(col2, BoxLayout.PAGE_AXIS));
        col2.add(boxScanner);
        col2.add(boxSequencer);
        col2.add(inScope);
        col2.setAlignmentY(Component.TOP_ALIGNMENT);

        JPanel col3 = new JPanel();
        col3.setLayout(new BoxLayout(col3, BoxLayout.PAGE_AXIS));
        col3.add(boxSpider);
        col3.add(boxProxy);
        
        col3.setAlignmentY(Component.TOP_ALIGNMENT);

        scopePanel.add(col1);
        scopePanel.add(col2);
        scopePanel.add(col3);

        JLabel domainHeader = new JLabel("Domains");
        domainHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainHeader.setForeground(BURP_ORANGE);
        domainHeader.setFont(headerFont);
        domainHeader.setBorder(new EmptyBorder(5, 0, 5, 0));

        JLabel domainHelp = new JLabel("<html><body style='width:520px'>Add one or more hosts and ATOR updates only those domains. "
        		+ "*.example.com includes that domain and its subdomains. host:port pins a port. "
        		+ "Clear the list to handle every host again.</body></html>");
        domainHelp.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainHelp.setBorder(new EmptyBorder(0, 0, 8, 0));

        onlyDomains = new JCheckBox("Only selected domains", false);
        onlyDomains.setAlignmentX(Component.LEFT_ALIGNMENT);
        onlyDomains.addActionListener(event -> DomainFilter.setEnabled(onlyDomains.isSelected()));

        domainField = new JTextField(28);
        JButton addDomain = new JButton("Add");
        addDomain.addActionListener(event -> addDomainFromField());
        domainField.addActionListener(event -> addDomainFromField());

        JPanel addDomainRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        addDomainRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        addDomainRow.add(domainField);
        addDomainRow.add(addDomain);

        JList<String> domainList = new JList<>(DOMAIN_MODEL);
        domainList.setVisibleRowCount(5);
        domainList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane domainScroll = new JScrollPane(domainList);
        domainScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainScroll.setPreferredSize(new Dimension(420, 120));
        domainScroll.setMaximumSize(new Dimension(Short.MAX_VALUE, 140));

        JButton removeDomain = new JButton("Remove");
        removeDomain.addActionListener(event -> removeSelectedDomains(domainList));
        JButton clearDomains = new JButton("Clear");
        clearDomains.addActionListener(event -> confirmClearDomains(clearDomains));

        JPanel domainButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        domainButtons.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainButtons.add(removeDomain);
        domainButtons.add(clearDomains);

        domainStatus = new JLabel(" ");
        domainStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainStatus.setBorder(new EmptyBorder(4, 0, 0, 0));
        domainError = new JLabel(" ");
        domainError.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainError.setForeground(new Color(180, 30, 30));

        bindDomains();

        JLabel importconfig = new JLabel("Import ATOR config");
        importconfig.setAlignmentX(Component.LEFT_ALIGNMENT);
        importconfig.setForeground(BURP_ORANGE);
        importconfig.setFont(headerFont);
        importconfig.setBorder(new EmptyBorder(5, 0, 5, 0));
        
        
        exportATOR = new JButton("Export ATOR");
        exportATOR.setEnabled(true);
        exportATOR.setAlignmentX(Component.LEFT_ALIGNMENT);
        exportATOR.addActionListener(new MenuAllListener(callbacks, this, MenuActions.EXPORT_CONFIG));
        
        JPanel importPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        importPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        
        JPanel exportPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        exportPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel exportconfig = new JLabel("Export ATOR config");
        exportconfig.setAlignmentX(Component.LEFT_ALIGNMENT);
        exportconfig.setForeground(BURP_ORANGE);
        exportconfig.setFont(headerFont);
        exportconfig.setBorder(new EmptyBorder(5, 0, 5, 0));
        
        importATOR = new JButton("Import ATOR");
        importATOR.setEnabled(true);
        importATOR.setAlignmentX(Component.LEFT_ALIGNMENT);
        importATOR.addActionListener(new MenuAllListener(callbacks, this, MenuActions.IMPORT_CONFIG));
       
        importATORFile = new JLabel();
        importATORFile.setFont(new java.awt.Font("Arial", 0, 15));
        importPanel.add(importATOR);
        importPanel.add(importATORFile);
        
        exportATORFile = new JLabel();
        exportATORFile.setFont(new java.awt.Font("Arial", 0, 15));
        exportPanel.add(exportATOR);
        exportPanel.add(exportATORFile);
        
        // Put it all together
        JPanel confPanel = new JPanel();
        confPanel.setLayout(new BoxLayout(confPanel, BoxLayout.Y_AXIS));
        confPanel.setBorder(new EmptyBorder(5, 15, 5, 15));

        confPanel.add(header1);
        confPanel.add(label2);
        confPanel.add(toggleScopesButton);
        confPanel.add(scopePanel);
        confPanel.add(domainHeader);
        confPanel.add(domainHelp);
        confPanel.add(onlyDomains);
        confPanel.add(addDomainRow);
        confPanel.add(domainScroll);
        confPanel.add(domainButtons);
        confPanel.add(domainStatus);
        confPanel.add(domainError);

        confPanel.add(importconfig);
        confPanel.add(importPanel);
        confPanel.add(exportconfig);
        confPanel.add(exportPanel);
        
        JScrollPane settingsScroll = new JScrollPane(confPanel);
        settingsScroll.setBorder(null);
        settingsScroll.getVerticalScrollBar().setUnitIncrement(16);
        settingsTab.add("General", settingsScroll);
        
        return settingsTab;
    }

    private void bindDomains() {
        DomainFilter.ensureLoaded();
        if (!domainListenerRegistered) {
            domainListenerRegistered = true;
            DomainFilter.setListener(this::reloadDomains);
        }
        reloadDomains();
    }

    private void reloadDomains() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::reloadDomains);
            return;
        }
        DOMAIN_MODEL.clear();
        for (String host : DomainFilter.patterns()) {
            DOMAIN_MODEL.addElement(host);
        }
        if (onlyDomains != null) {
            onlyDomains.setSelected(DomainFilter.isEnabled());
        }
        if (domainStatus != null) {
            domainStatus.setText(DomainFilter.statusText());
        }
    }

    private void addDomainFromField() {
        String normalized = DomainFilter.add(domainField.getText());
        if (normalized == null) {
            domainError.setText("Use a host such as api.example.com, *.example.com, or api.example.com:8443.");
            return;
        }
        domainField.setText("");
        domainError.setText(" ");
    }

    private void removeSelectedDomains(JList<String> domainList) {
        List<String> selected = domainList.getSelectedValuesList();
        if (selected.isEmpty()) {
            domainError.setText("Select a domain to remove.");
            return;
        }
        DomainFilter.remove(selected);
        domainError.setText(" ");
    }

    private void confirmClearDomains(JButton source) {
        if (DomainFilter.patterns().isEmpty()) {
            domainError.setText(" ");
            return;
        }
        int choice = JOptionPane.showConfirmDialog(source,
                "Clear the domain list and handle every host?",
                "ATOR domains",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }
        DomainFilter.clear();
        domainError.setText(" ");
    }
	
	public static boolean isToolEnabled(int toolFlag) {
    	switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return selected(boxIntruder, true);

            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return selected(boxRepeater, true);

            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return selected(boxScanner, true);

            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return selected(boxSequencer, true);

            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return selected(boxSpider, true);

            case IBurpExtenderCallbacks.TOOL_PROXY:
                return selected(boxProxy, true);
            
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return selected(boxExtender, true);
        }
        return false;
    }

	public static boolean isToolEnabled(burp.api.montoya.core.ToolType tool) {
		if (tool == null) {
			return false;
		}
		switch (tool) {
			case INTRUDER:
				return selected(boxIntruder, true);
			case REPEATER:
				return selected(boxRepeater, true);
			case SCANNER:
				return selected(boxScanner, true);
			case SEQUENCER:
				return selected(boxSequencer, true);
			case PROXY:
				return selected(boxProxy, true);
			case EXTENSIONS:
				return selected(boxExtender, true);
			case BURP_AI:
				return selected(boxBurpAi, true);
			default:
				return false;
		}
	}

	private static boolean selected(JCheckBox box, boolean whenUnset) {
		return box == null ? whenUnset : box.isSelected();
	}
	
	public boolean isEnabledAtLeastOne() {
	    return  selected(boxIntruder, true) ||
	            selected(boxRepeater, true) ||
	            selected(boxScanner, true) ||
	            selected(boxSequencer, true) ||
	            selected(boxProxy, true) ||
	            selected(boxSpider, true) ||
	            selected(boxExtender, true) ||
	            selected(boxBurpAi, true);
	}
	
	public void setAllTools(boolean enabled) {
        boxRepeater.setSelected(enabled);
        boxIntruder.setSelected(enabled);
        boxScanner.setSelected(enabled);
        boxSequencer.setSelected(enabled);
        boxSpider.setSelected(enabled);
        boxProxy.setSelected(enabled);
        boxExtender.setSelected(enabled);
        boxBurpAi.setSelected(enabled);
        inScope.setSelected(enabled);
    }
	
	
}
