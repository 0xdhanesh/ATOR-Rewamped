package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.utilities.json.JsonArrayNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;

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
                default:
                    return json(400, error("Unknown command '" + command + "'. Use status, refresh, export, or import."));
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
        root.putString("version", "2.4.1");
        root.putString("sessionHandlingAction", AtorSessionAction.NAME);
        root.putBoolean("preview", PreviewPanel.isPreviewEnabled);
        root.putBoolean("inScopeOnly", SetttingsTab.inScope != null && SetttingsTab.inScope.isSelected());
        root.putString("trigger", PreviewPanel.conditionDetails == null ? "" : PreviewPanel.conditionDetails.getText());
        root.put("tools", tools());
        root.put("extractions", extractions(includeValues));
        root.putNumber("obtainSteps", ObtainPanel.obtainEntrylist.size());
        root.putNumber("replacements", ReplacePanel.replaceEntrylist.size());
        root.putNumber("errorConditions", ErrorPanel.errorEntrylist.size());
        root.putString("commandHeader", AtorHttpHandler.COMMAND_HEADER);
        root.putString("commands", "status, refresh, export, import");
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
