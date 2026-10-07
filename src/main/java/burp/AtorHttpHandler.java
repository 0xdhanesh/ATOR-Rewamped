package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Live ATOR hook for every Burp tool, including requests that burp-mcp sends
 * through {@code api.http().sendRequest} (tool type Extensions).
 *
 * <p>Control plane, accepted only from Extensions, Burp AI, and Repeater so a
 * proxied browser cannot invoke it. Add header {@code X-ATOR-Command} with
 * {@code status}, {@code refresh}, {@code export}, or {@code import}. The
 * request is not forwarded. {@code import} reads the HTTP body as an ATOR
 * export document.
 */
public final class AtorHttpHandler implements HttpHandler {
    static final String COMMAND_HEADER = "X-ATOR-Command";
    static final String MACRO_HEADER = "X-ATOR-Macro";

    private static final ThreadLocal<Integer> DEPTH = ThreadLocal.withInitial(() -> 0);

    static void enter() {
        DEPTH.set(DEPTH.get() + 1);
    }

    static void exit() {
        int next = DEPTH.get() - 1;
        if (next <= 0) {
            DEPTH.remove();
        } else {
            DEPTH.set(next);
        }
    }

    static boolean inCall() {
        return DEPTH.get() > 0;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            if (inCall() || request.hasHeader(MACRO_HEADER)) {
                HttpRequest stripped = request.hasHeader(MACRO_HEADER)
                        ? request.withRemovedHeader(MACRO_HEADER)
                        : request;
                return RequestToBeSentAction.continueWith(stripped);
            }
            if (request.hasHeader(COMMAND_HEADER) && controlPlane(request.toolSource())) {
                return RequestToBeSentAction.spoof(AtorCommands.execute(request));
            }
            if (!shouldHandle(request.toolSource(), request)) {
                return RequestToBeSentAction.continueWith(request);
            }
            HttpRequest updated = AtorEngine.apply(request);
            if (updated != null && updated != request && !updated.toString().equals(request.toString())) {
                String tool = request.toolSource() == null || request.toolSource().toolType() == null
                        ? "Burp"
                        : request.toolSource().toolType().toString();
                BurpExtender.log("ATOR updated " + tool + " " + request.method() + " " + request.path());
            }
            return RequestToBeSentAction.continueWith(updated == null ? request : updated);
        } catch (Exception e) {
            BurpExtender.log("ATOR request handler: " + e.getMessage());
            return RequestToBeSentAction.continueWith(request);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            if (inCall() || response.hasHeader(MACRO_HEADER)) {
                return ResponseReceivedAction.continueWith(response);
            }
            HttpRequest initiating = response.initiatingRequest();
            if (initiating != null && initiating.hasHeader(COMMAND_HEADER)) {
                return ResponseReceivedAction.continueWith(response);
            }
            if (!shouldHandle(response.toolSource(), initiating)) {
                return ResponseReceivedAction.continueWith(response);
            }
            if (!CheckCondition.matches(response)) {
                return ResponseReceivedAction.continueWith(response);
            }
            HttpResponse refreshed = AtorEngine.refreshAndRetry(initiating);
            if (refreshed == null) {
                return ResponseReceivedAction.continueWith(response);
            }
            Annotations notes = response.annotations() == null
                    ? Annotations.annotations("ATOR refreshed this response")
                    : response.annotations().withNotes("ATOR refreshed this response");
            return ResponseReceivedAction.continueWith(refreshed, notes);
        } catch (Exception e) {
            BurpExtender.log("ATOR response handler: " + e.getMessage());
            return ResponseReceivedAction.continueWith(response);
        }
    }

    static boolean controlPlane(ToolSource source) {
        if (source == null) {
            return false;
        }
        ToolType tool = source.toolType();
        return tool == ToolType.EXTENSIONS || tool == ToolType.BURP_AI || tool == ToolType.REPEATER;
    }

    private static boolean shouldHandle(ToolSource source, HttpRequest request) {
        if (PreviewPanel.isPreviewEnabled) {
            return false;
        }
        if (source == null || !SetttingsTab.isToolEnabled(source.toolType())) {
            return false;
        }
        if (SetttingsTab.inScope != null && SetttingsTab.inScope.isSelected()) {
            try {
                if (request == null || !request.isInScope()) {
                    return false;
                }
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }
}
