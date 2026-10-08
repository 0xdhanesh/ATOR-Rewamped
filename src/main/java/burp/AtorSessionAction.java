package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;

/**
 * Official session-handling action. The name is {@code ATOR}.
 * Burp session rules, including rules written by burp-mcp
 * {@code set_project_options}, invoke this before the request is sent.
 */
public final class AtorSessionAction implements SessionHandlingAction {
    static final String NAME = "ATOR";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        HttpRequest request = actionData.request();
        try {
            if (!PreviewPanel.isPreviewEnabled && AtorHttpHandler.domainAllowed(request)) {
                AtorEngine.ensureTokens();
                request = AtorEngine.apply(request);
            }
        } catch (Exception e) {
            BurpExtender.log("ATOR session action: " + e.getMessage());
        }
        if (actionData.annotations() == null) {
            return ActionResult.actionResult(request);
        }
        return ActionResult.actionResult(request, actionData.annotations());
    }
}
