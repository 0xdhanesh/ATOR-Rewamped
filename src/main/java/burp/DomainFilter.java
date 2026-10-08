package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Hosts ATOR is willing to update. An empty list with the filter off handles
 * every host, which is the v2.4.1 behavior. A leading {@code *.} includes the
 * domain and its subdomains. {@code host:port} pins a port.
 */
public final class DomainFilter {
    static final String SETTING_DOMAINS = "ator.domains";
    static final String SETTING_ENABLED = "ator.domains.enabled";

    private static final Object LOCK = new Object();
    private static volatile State state = new State(false, List.of());
    private static volatile Runnable listener;
    private static boolean checkedPreferences;
    private static boolean checkedLegacy;

    private DomainFilter() {
    }

    public static void setListener(Runnable listener) {
        DomainFilter.listener = listener;
    }

    public static boolean isEnabled() {
        ensureLoaded();
        return state.enabled;
    }

    public static List<String> patterns() {
        ensureLoaded();
        return state.patterns;
    }

    public static String statusText() {
        ensureLoaded();
        State current = state;
        if (current.enabled && current.patterns.isEmpty()) {
            return "The domain list is empty, so ATOR leaves traffic unchanged.";
        }
        if (!current.enabled || current.patterns.isEmpty()) {
            return "ATOR handles every host.";
        }
        int count = current.patterns.size();
        return "ATOR handles " + count + (count == 1 ? " domain." : " domains.");
    }

    /**
     * @return the stored pattern, or null when {@code raw} is not a host
     */
    public static String add(String raw) {
        String normalized = normalize(raw);
        if (normalized == null) {
            return null;
        }
        boolean changed = false;
        synchronized (LOCK) {
            ensureLoadedLocked();
            State current = state;
            if (current.patterns.contains(normalized) && current.enabled) {
                return normalized;
            }
            List<String> next = new ArrayList<>(current.patterns);
            if (!next.contains(normalized)) {
                next.add(normalized);
            }
            state = new State(true, List.copyOf(next));
            persist();
            changed = true;
        }
        if (changed) {
            notifyListener();
        }
        return normalized;
    }

    public static void remove(Collection<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return;
        }
        synchronized (LOCK) {
            ensureLoadedLocked();
            List<String> next = new ArrayList<>(state.patterns);
            for (String host : hosts) {
                if (host == null) {
                    continue;
                }
                next.remove(host);
                String normalized = normalize(host);
                if (normalized != null) {
                    next.remove(normalized);
                }
            }
            boolean enabled = state.enabled && !next.isEmpty();
            state = new State(enabled, List.copyOf(next));
            persist();
        }
        notifyListener();
    }

    public static void clear() {
        synchronized (LOCK) {
            ensureLoadedLocked();
            state = new State(false, List.of());
            persist();
        }
        notifyListener();
    }

    public static void setEnabled(boolean enabled) {
        synchronized (LOCK) {
            ensureLoadedLocked();
            if (state.enabled == enabled) {
                return;
            }
            state = new State(enabled, state.patterns);
            persist();
        }
        notifyListener();
    }

    /**
     * Replaces the list. When {@code enabledFlag} is null, the filter turns on
     * if at least one host survived normalization.
     */
    public static void setPatterns(List<String> raw, Boolean enabledFlag) {
        List<String> next = normalizeAll(raw);
        boolean enabled = enabledFlag != null ? enabledFlag : !next.isEmpty();
        synchronized (LOCK) {
            ensureLoadedLocked();
            state = new State(enabled, List.copyOf(next));
            persist();
        }
        notifyListener();
    }

    public static List<String> invalid(List<String> raw) {
        List<String> bad = new ArrayList<>();
        if (raw == null) {
            return bad;
        }
        for (String item : raw) {
            if (item == null || item.isBlank()) {
                bad.add("(blank)");
                continue;
            }
            if (normalize(item) == null) {
                bad.add(item.trim());
            }
        }
        return bad;
    }

    public static boolean allows(String host, int port) {
        State current;
        synchronized (LOCK) {
            ensureLoadedLocked();
            current = state;
        }
        if (!current.enabled) {
            return true;
        }
        if (current.patterns.isEmpty() || host == null || host.isBlank()) {
            return false;
        }
        String requestHost = canonicalHost(host);
        if (requestHost.isEmpty()) {
            return false;
        }
        for (String pattern : current.patterns) {
            if (matches(pattern, requestHost, port)) {
                return true;
            }
        }
        return false;
    }

    public static void ensureLoaded() {
        synchronized (LOCK) {
            ensureLoadedLocked();
        }
    }

    public static String normalize(String raw) {
        if (raw == null) {
            return null;
        }
        String text = raw.trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty() || hasWhitespace(text)) {
            return null;
        }
        int scheme = text.indexOf("://");
        if (scheme >= 0) {
            text = text.substring(scheme + 3);
        }
        int slash = text.indexOf('/');
        if (slash >= 0) {
            text = text.substring(0, slash);
        }
        int query = text.indexOf('?');
        if (query >= 0) {
            text = text.substring(0, query);
        }
        int hash = text.indexOf('#');
        if (hash >= 0) {
            text = text.substring(0, hash);
        }
        int at = text.lastIndexOf('@');
        if (at >= 0) {
            text = text.substring(at + 1);
        }
        if (text.isEmpty()) {
            return null;
        }

        String host;
        String portText = null;
        if (text.startsWith("[")) {
            int end = text.indexOf(']');
            if (end <= 1) {
                return null;
            }
            String inner = text.substring(1, end);
            if (!validIpv6(inner)) {
                return null;
            }
            host = "[" + inner + "]";
            String rest = text.substring(end + 1);
            if (!rest.isEmpty()) {
                if (!rest.startsWith(":") || rest.length() == 1) {
                    return null;
                }
                portText = rest.substring(1);
            }
        } else {
            int colon = text.indexOf(':');
            int lastColon = text.lastIndexOf(':');
            if (colon >= 0 && colon != lastColon) {
                if (!validIpv6(text)) {
                    return null;
                }
                return text;
            }
            if (colon >= 0) {
                host = text.substring(0, colon);
                portText = text.substring(colon + 1);
            } else {
                host = text;
            }
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.startsWith("[")) {
            if (portText == null) {
                return host;
            }
            Integer bracketPort = parsePort(portText);
            if (bracketPort == null) {
                return null;
            }
            return host + ":" + bracketPort;
        }
        if (!validHostname(host)) {
            return null;
        }
        if (portText == null) {
            return host;
        }
        Integer port = parsePort(portText);
        if (port == null) {
            return null;
        }
        return host + ":" + port;
    }

    private static void ensureLoadedLocked() {
        boolean apiReady = BurpExtender.api != null;
        boolean legacyReady = BurpExtender.callbacks != null;
        if ((!apiReady || checkedPreferences) && (!legacyReady || checkedLegacy)) {
            return;
        }
        if (apiReady) {
            checkedPreferences = true;
        }
        if (legacyReady) {
            checkedLegacy = true;
        }
        if (state.enabled || !state.patterns.isEmpty()) {
            return;
        }
        Stored stored = readStored();
        if (stored == null) {
            return;
        }
        List<String> patterns = normalizeAll(stored.lines);
        boolean enabled = stored.enabled != null ? stored.enabled : !patterns.isEmpty();
        state = new State(enabled, List.copyOf(patterns));
    }

    private static Stored readStored() {
        MontoyaApi api = BurpExtender.api;
        if (api != null) {
            try {
                Preferences preferences = api.persistence().preferences();
                String raw = preferences.getString(SETTING_DOMAINS);
                Boolean enabled = preferences.getBoolean(SETTING_ENABLED);
                if (raw != null || enabled != null) {
                    return Stored.from(raw, enabled);
                }
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not load domains: " + e.getMessage());
            }
        }
        IBurpExtenderCallbacks callbacks = BurpExtender.callbacks;
        if (callbacks != null) {
            try {
                String raw = callbacks.loadExtensionSetting(SETTING_DOMAINS);
                String flag = callbacks.loadExtensionSetting(SETTING_ENABLED);
                if (raw != null || flag != null) {
                    Boolean enabled = flag == null ? null : Boolean.valueOf(flag);
                    return Stored.from(raw, enabled);
                }
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not load domains: " + e.getMessage());
            }
        }
        return null;
    }

    private static void persist() {
        State current = state;
        String joined = String.join("\n", current.patterns);
        MontoyaApi api = BurpExtender.api;
        if (api != null) {
            try {
                Preferences preferences = api.persistence().preferences();
                if (joined.isEmpty()) {
                    preferences.deleteString(SETTING_DOMAINS);
                } else {
                    preferences.setString(SETTING_DOMAINS, joined);
                }
                preferences.setBoolean(SETTING_ENABLED, current.enabled);
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not save domains: " + e.getMessage());
            }
        }
        IBurpExtenderCallbacks callbacks = BurpExtender.callbacks;
        if (callbacks != null) {
            try {
                callbacks.saveExtensionSetting(SETTING_DOMAINS, joined.isEmpty() ? null : joined);
                callbacks.saveExtensionSetting(SETTING_ENABLED, Boolean.toString(current.enabled));
            } catch (RuntimeException e) {
                BurpExtender.log("ATOR could not save domains: " + e.getMessage());
            }
        }
    }

    private static void notifyListener() {
        Runnable current = listener;
        if (current == null) {
            return;
        }
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                current.run();
            } else {
                SwingUtilities.invokeLater(current);
            }
        } catch (RuntimeException e) {
            BurpExtender.log("ATOR domain list: " + e.getMessage());
        }
    }

    private static List<String> normalizeAll(List<String> raw) {
        List<String> next = new ArrayList<>();
        if (raw == null) {
            return next;
        }
        for (String item : raw) {
            String normalized = normalize(item);
            if (normalized != null && !next.contains(normalized)) {
                next.add(normalized);
            }
        }
        return next;
    }

    private static boolean matches(String pattern, String requestHost, int port) {
        HostPort parsed = split(pattern);
        if (parsed.port != -1 && parsed.port != port) {
            return false;
        }
        String patternHost = canonicalHost(parsed.host);
        if (patternHost.startsWith("*.")) {
            String suffix = patternHost.substring(2);
            return requestHost.equals(suffix) || requestHost.endsWith("." + suffix);
        }
        return requestHost.equals(patternHost);
    }

    private static HostPort split(String pattern) {
        if (pattern.startsWith("[")) {
            int end = pattern.indexOf(']');
            String host = pattern.substring(0, end + 1);
            if (end + 1 < pattern.length() && pattern.charAt(end + 1) == ':') {
                return new HostPort(host, Integer.parseInt(pattern.substring(end + 2)));
            }
            return new HostPort(host, -1);
        }
        int first = pattern.indexOf(':');
        int last = pattern.lastIndexOf(':');
        if (first >= 0 && first != last) {
            return new HostPort(pattern, -1);
        }
        if (first >= 0) {
            return new HostPort(pattern.substring(0, first), Integer.parseInt(pattern.substring(first + 1)));
        }
        return new HostPort(pattern, -1);
    }

    private static String canonicalHost(String host) {
        String value = host.trim().toLowerCase(Locale.ROOT);
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.startsWith("[") && value.endsWith("]") && value.length() > 2) {
            value = value.substring(1, value.length() - 1);
        }
        return value;
    }

    private static boolean validHostname(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return false;
        }
        if (host.startsWith("*.")) {
            host = host.substring(2);
            if (host.isEmpty() || host.indexOf('*') >= 0) {
                return false;
            }
        } else if (host.indexOf('*') >= 0) {
            return false;
        }
        String[] labels = host.split("\\.", -1);
        if (labels.length == 0) {
            return false;
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(Character.isLetterOrDigit(c) || c == '-' || c == '_')) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean validIpv6(String host) {
        int colons = 0;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == ':') {
                colons++;
            } else if (c == '%') {
                return i > 0 && colons >= 2;
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return colons >= 2;
    }

    private static Integer parsePort(String portText) {
        if (portText == null || portText.isEmpty() || portText.length() > 5) {
            return null;
        }
        int port = 0;
        for (int i = 0; i < portText.length(); i++) {
            char c = portText.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            port = port * 10 + (c - '0');
        }
        if (port < 1 || port > 65535) {
            return null;
        }
        return port;
    }

    private static boolean hasWhitespace(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (Character.isWhitespace(text.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static final class State {
        private final boolean enabled;
        private final List<String> patterns;

        private State(boolean enabled, List<String> patterns) {
            this.enabled = enabled;
            this.patterns = patterns;
        }
    }

    private static final class HostPort {
        private final String host;
        private final int port;

        private HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static final class Stored {
        private final List<String> lines;
        private final Boolean enabled;

        private Stored(List<String> lines, Boolean enabled) {
            this.lines = lines;
            this.enabled = enabled;
        }

        private static Stored from(String raw, Boolean enabled) {
            List<String> lines = new ArrayList<>();
            if (raw != null && !raw.isBlank()) {
                for (String line : raw.split("\\R")) {
                    lines.add(line);
                }
            }
            return new Stored(lines, enabled);
        }
    }
}
