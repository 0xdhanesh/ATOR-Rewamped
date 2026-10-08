package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.utilities.json.JsonArrayNode;
import burp.api.montoya.utilities.json.JsonObjectNode;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.utilities.json.JsonArrayNode.jsonArrayNode;
import static burp.api.montoya.utilities.json.JsonObjectNode.jsonObjectNode;

/**
 * Functions burp-mcp calls with the existing {@code send_http1_request} or
 * {@code send_http2_request} tool. The header is {@code X-ATOR-Command}.
 */
public final class AtorCommands {
    private AtorCommands() {
    }

    public static HttpResponse execute(HttpRequest request) {
        String command = request.headerValue(AtorHttpHandler.COMMAND_HEADER);
        if (command == null) {
            return json(400, error("Missing " + AtorHttpHandler.COMMAND_HEADER));
        }
        command = command.trim().toLowerCase();
        try {
            switch (command) {
                case "status":
                    JsonObjectNode current = status(true);
                    current.putBoolean("ok", true);
                    current.putString("action", "status");
                    return json(200, current.toJsonString());
                case "refresh":
                    AtorEngine.runObtain();
                    JsonObjectNode refreshed = status(true);
                    refreshed.putBoolean("ok", true);
                    refreshed.putString("action", "refresh");
                    return json(200, refreshed.toJsonString());
                case "export":
                    return json(200, exportConfig());
                case "import":
                    return json(200, importConfig(request.bodyToString()));
                case "domains":
                    return json(200, setDomains(request.bodyToString()));
                default:
                    return json(400, error("Unknown command '" + command + "'. Use status, refresh, export, import, or domains."));
            }
        } catch (Exception e) {
            Throwable reported = e;
            while (reported.getCause() != null && reported.getMessage() == null) {
                reported = reported.getCause();
            }
            if (reported.getCause() != null && reported instanceof RuntimeException) {
                reported = reported.getCause();
            }
            String message = reported.getMessage() == null ? reported.toString() : reported.getMessage();
            BurpExtender.log("ATOR command " + command + " failed: " + message);
            return json(500, error(message));
        }
    }

    private static JsonObjectNode status(boolean includeValues) {
        JsonObjectNode root = jsonObjectNode();
        root.putString("extension", "ATOR");
        root.putString("version", BurpExtender.VERSION);
        root.putString("sessionHandlingAction", AtorSessionAction.NAME);
        root.putBoolean("preview", PreviewPanel.isPreviewEnabled);
        root.putBoolean("inScopeOnly", SetttingsTab.inScope != null && SetttingsTab.inScope.isSelected());
        root.putBoolean("domainsEnabled", DomainFilter.isEnabled());
        root.put("domains", domainNodes());
        root.putString("trigger", PreviewPanel.conditionDetails == null ? "" : PreviewPanel.conditionDetails.getText());
        root.put("tools", tools());
        root.put("extractions", extractions(includeValues));
        root.putNumber("obtainSteps", ObtainPanel.obtainEntrylist.size());
        root.putNumber("replacements", ReplacePanel.replaceEntrylist.size());
        root.putNumber("errorConditions", ErrorPanel.errorEntrylist.size());
        root.putString("commandHeader", AtorHttpHandler.COMMAND_HEADER);
        root.putString("commands", "status, refresh, export, import, domains");
        return root;
    }

    private static JsonArrayNode tools() {
        JsonArrayNode tools = jsonArrayNode();
        addTool(tools, "Repeater", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.REPEATER));
        addTool(tools, "Intruder", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.INTRUDER));
        addTool(tools, "Scanner", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.SCANNER));
        addTool(tools, "Sequencer", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.SEQUENCER));
        addTool(tools, "Proxy", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.PROXY));
        addTool(tools, "Extensions", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.EXTENSIONS));
        addTool(tools, "Burp AI", SetttingsTab.isToolEnabled(burp.api.montoya.core.ToolType.BURP_AI));
        return tools;
    }

    private static void addTool(JsonArrayNode tools, String name, boolean enabled) {
        JsonObjectNode tool = jsonObjectNode();
        tool.putString("name", name);
        tool.putBoolean("enabled", enabled);
        tools.add(tool);
    }

    private static JsonArrayNode extractions(boolean includeValues) {
        JsonArrayNode list = jsonArrayNode();
        synchronized (ObtainPanel.extractionEntrylist) {
            for (ExtractionEntry entry : ObtainPanel.extractionEntrylist) {
                JsonObjectNode item = jsonObjectNode();
                item.putString("name", entry.getName() == null ? "" : entry.getName());
                boolean present = entry.value != null && !entry.value.isEmpty() && !AtorEngine.isSentinel(entry.value);
                item.putBoolean("present", present);
                item.putNumber("length", entry.value == null ? 0 : entry.value.length());
                if (includeValues && present) {
                    item.putString("value", entry.value);
                }
                list.add(item);
            }
        }
        return list;
    }

    private static String exportConfig() {
        if (BurpExtender.callbacks == null) {
            return error("ATOR UI is not ready");
        }
        ExportATOR exporter = new ExportATOR(BurpExtender.callbacks);
        JsonObjectNode wrapper = jsonObjectNode();
        wrapper.putBoolean("ok", true);
        wrapper.putString("action", "export");
        wrapper.putString("config", exporter.exportATOR().toJSONString());
        return wrapper.toJsonString();
    }

    private static String importConfig(String body) throws Exception {
        if (body == null || body.isBlank()) {
            return error("import requires the ATOR export JSON as the request body");
        }
        if (BurpExtender.callbacks == null) {
            return error("ATOR UI is not ready");
        }
        final String payload = body;
        Runnable task = () -> {
            try {
                new ImportATOR(BurpExtender.callbacks).importFromString(payload);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage() == null ? e.toString() : e.getMessage(), e);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeAndWait(task);
        }
        JsonObjectNode wrapper = status(false);
        wrapper.putBoolean("ok", true);
        wrapper.putString("action", "import");
        return wrapper.toJsonString();
    }

    private static JsonArrayNode domainNodes() {
        JsonArrayNode list = jsonArrayNode();
        for (String host : DomainFilter.patterns()) {
            list.addString(host);
        }
        return list;
    }

    private static String setDomains(String body) throws Exception {
        DomainCommand parsed = parseDomains(body);
        if (parsed.error != null) {
            return error(parsed.error);
        }
        Runnable task = () -> DomainFilter.setPatterns(parsed.domains, parsed.enabled);
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
        } else {
            SwingUtilities.invokeAndWait(task);
        }
        JsonObjectNode wrapper = status(false);
        wrapper.putBoolean("ok", true);
        wrapper.putString("action", "domains");
        return wrapper.toJsonString();
    }

    private static DomainCommand parseDomains(String body) {
        if (body == null || body.isBlank()) {
            return DomainCommand.error("domains requires a JSON array, {\"domains\":[...]}, or one host per line. Send {\"domains\":[]} to handle every host.");
        }
        String trimmed = body.trim();
        try {
            if (trimmed.startsWith("[")) {
                Object parsed = new JSONParser().parse(trimmed);
                if (!(parsed instanceof JSONArray)) {
                    return DomainCommand.error("domains body must be a JSON array of hosts.");
                }
                return fromHosts(readArray((JSONArray) parsed), null);
            }
            if (trimmed.startsWith("{")) {
                Object parsed = new JSONParser().parse(trimmed);
                if (!(parsed instanceof JSONObject)) {
                    return DomainCommand.error("domains body must be a JSON object with a domains array.");
                }
                JSONObject object = (JSONObject) parsed;
                if (!object.containsKey("domains") && !object.containsKey("enabled") && !object.containsKey("domainsEnabled")) {
                    return DomainCommand.error("domains object needs \"domains\" or \"enabled\".");
                }
                List<String> hosts = null;
                if (object.containsKey("domains")) {
                    Object raw = object.get("domains");
                    if (raw instanceof JSONArray) {
                        hosts = readArray((JSONArray) raw);
                    } else if (raw instanceof String) {
                        hosts = new ArrayList<>();
                        hosts.add((String) raw);
                    } else {
                        return DomainCommand.error("domains must be an array of hosts.");
                    }
                }
                Boolean enabled = null;
                if (object.containsKey("enabled")) {
                    enabled = booleanValue(object.get("enabled"));
                } else if (object.containsKey("domainsEnabled")) {
                    enabled = booleanValue(object.get("domainsEnabled"));
                }
                if (hosts == null) {
                    hosts = new ArrayList<>(DomainFilter.patterns());
                }
                return fromHosts(hosts, enabled);
            }
        } catch (Exception e) {
            String message = e.getMessage() == null ? e.toString() : e.getMessage();
            return DomainCommand.error("Could not read domains: " + message);
        }
        List<String> hosts = new ArrayList<>();
        boolean any = false;
        for (String line : trimmed.split("\\R")) {
            String item = line.trim();
            if (item.isEmpty() || item.startsWith("#")) {
                continue;
            }
            any = true;
            hosts.add(item);
        }
        if (!any) {
            return DomainCommand.error("domains requires a JSON array, {\"domains\":[...]}, or one host per line. Send {\"domains\":[]} to handle every host.");
        }
        return fromHosts(hosts, null);
    }

    private static DomainCommand fromHosts(List<String> hosts, Boolean enabled) {
        List<String> invalid = DomainFilter.invalid(hosts);
        if (!invalid.isEmpty()) {
            return DomainCommand.error("Invalid domain(s): " + String.join(", ", invalid));
        }
        return new DomainCommand(hosts, enabled, null);
    }

    private static List<String> readArray(JSONArray array) {
        List<String> hosts = new ArrayList<>();
        for (Object item : array) {
            if (item != null) {
                hosts.add(String.valueOf(item));
            }
        }
        return hosts;
    }

    private static Boolean booleanValue(Object value) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value == null) {
            return Boolean.FALSE;
        }
        return Boolean.valueOf(String.valueOf(value));
    }

    private static final class DomainCommand {
        private final List<String> domains;
        private final Boolean enabled;
        private final String error;

        private DomainCommand(List<String> domains, Boolean enabled, String error) {
            this.domains = domains;
            this.enabled = enabled;
            this.error = error;
        }

        private static DomainCommand error(String message) {
            return new DomainCommand(null, null, message);
        }
    }

    private static String error(String message) {
        JsonObjectNode root = jsonObjectNode();
        root.putBoolean("ok", false);
        root.putString("error", message == null ? "unknown error" : message);
        return root.toJsonString();
    }

    private static HttpResponse json(int status, String body) {
        String reason = status == 200 ? "OK" : (status == 500 ? "Error" : "Bad Request");
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "X-ATOR: 1\r\n"
                + "\r\n");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return response.withBody(burp.api.montoya.core.ByteArray.byteArray(bytes));
    }
}
