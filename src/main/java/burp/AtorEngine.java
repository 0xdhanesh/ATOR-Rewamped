package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Token obtain and replace. Message edits go through Montoya
 * {@code withPath}, {@code withUpdatedHeader}, and {@code withBody}, which keep
 * HTTP/2 messages intact on Burp 2026.8. The legacy listener rewrote the raw
 * byte array and dropped the HTTP/2 framing.
 */
public final class AtorEngine {
    private static final ReentrantLock REFRESH = new ReentrantLock();
    private static final String SENTINEL_SPOT = "Ext ERR on SPOT";
    private static final String SENTINEL_SPOT_COMPACT = "ExtERRonSPOT";
    private static final String SENTINEL_EXTRACT = "EXTRACTION_ERROR";

    private AtorEngine() {
    }

    public static HttpRequest apply(HttpRequest request) {
        if (request == null) {
            return null;
        }
        ensureTokens();
        List<ReplaceEntry> rules = copyReplaceRules();
        if (rules.isEmpty()) {
            return request;
        }
        String contentType = contentTypeOf(request);
        String raw = request.toString();
        String urlText = request.method() + " " + request.path() + " " + request.httpVersion();
        String headers = headerSection(raw);
        String body = request.bodyToString() == null ? "" : request.bodyToString();
        HttpRequest updated = request;
        for (ReplaceEntry rule : rules) {
            String extracted = findCurrentValue(rule, urlText, headers, body, contentType);
            if (isSentinel(extracted) || extracted.isEmpty()) {
                extracted = selectedFallback(rule, headers, body, urlText);
            }
            if (isSentinel(extracted) || extracted.isEmpty()) {
                continue;
            }
            String value = extractionValue(rule.getextractionName());
            if (value == null) {
                continue;
            }
            value = Extraction.removeemptyCharacter(value);
            updated = replaceInSection(updated, rule.getReplacementIn(), extracted, value);
            if (updated == request || updated.toString().equals(raw)) {
                updated = replaceHttp1Raw(updated, extracted, value);
            }
            raw = updated.toString();
            body = updated.bodyToString() == null ? "" : updated.bodyToString();
            headers = headerSection(raw);
            urlText = updated.method() + " " + updated.path() + " " + updated.httpVersion();
        }
        return updated;
    }

    public static void ensureTokens() {
        if (missingToken()) {
            runObtain();
        }
    }

    public static HttpResponse refreshAndRetry(HttpRequest original) {
        if (original == null || copyObtainSteps().isEmpty()) {
            return null;
        }
        boolean locked = false;
        try {
            locked = REFRESH.tryLock(60, TimeUnit.SECONDS);
            if (!locked) {
                BurpExtender.log("ATOR refresh timed out waiting for the in-flight obtain macro");
                return null;
            }
            runObtain();
            HttpRequest updated = apply(original);
            HttpRequestResponse sent = send(updated, true);
            if (sent == null || sent.response() == null) {
                BurpExtender.log("ATOR retry returned no response");
                return null;
            }
            BurpExtender.log("ATOR refreshed the token and retried " + safeUrl(original));
            return sent.response();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (locked) {
                REFRESH.unlock();
            }
        }
    }

    public static void runObtain() {
        List<ObtainEntry> steps = copyObtainSteps();
        if (steps.isEmpty()) {
            return;
        }
        boolean locked = false;
        if (!REFRESH.isHeldByCurrentThread()) {
            try {
                locked = REFRESH.tryLock(60, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (!locked) {
                BurpExtender.log("ATOR obtain macro skipped; another refresh is still running");
                return;
            }
        }
        try {
            for (ObtainEntry step : steps) {
                runStep(step);
            }
            publishExtractionTable();
        } finally {
            if (locked) {
                REFRESH.unlock();
            }
        }
    }

    public static IHttpRequestResponse sendLegacy(IHttpService service, byte[] requestBytes) {
        if (service == null || requestBytes == null) {
            return new HttpRequestResponseImpl(requestBytes, new byte[0], null, null, service);
        }
        if (BurpExtender.api == null) {
            return BurpExtender.callbacks.makeHttpRequest(service, requestBytes);
        }
        boolean https = "https".equalsIgnoreCase(service.getProtocol());
        HttpService svc = HttpService.httpService(service.getHost(), service.getPort(), https);
        HttpRequest request = HttpRequest.httpRequest(svc, ByteArray.byteArray(requestBytes));
        HttpRequestResponse sent = send(request, true);
        byte[] responseBytes = sent != null && sent.response() != null
                ? sent.response().toByteArray().getBytes()
                : new byte[0];
        byte[] sentRequest = sent != null && sent.request() != null
                ? sent.request().toByteArray().getBytes()
                : requestBytes;
        return new HttpRequestResponseImpl(sentRequest, responseBytes, null, null, service);
    }

    static String findCurrentValue(ReplaceEntry rule, String urlText, String headers, String body, String contentType) {
        if (rule == null) {
            return SENTINEL_SPOT;
        }
        String where = rule.getReplacementIn() == null ? "" : rule.getReplacementIn();
        String start = rule.startString == null ? "" : rule.startString;
        String stop = rule.stopString == null ? "" : rule.stopString;
        String headerName = rule.headerName == null ? "" : rule.headerName;
        if ("URL".equals(where)) {
            return Extraction.extractingDataInURL(urlText, start, stop, SENTINEL_SPOT);
        }
        if ("BODY".equals(where) && contentType != null
                && (contentType.startsWith("application/json") || contentType.contains("multipart/form-data"))) {
            return Extraction.extractingInJsonBody(body == null ? "" : body, start, stop, SENTINEL_EXTRACT);
        }
        return Extraction.extractingDataInSpotError(headers == null ? "" : headers, start, stop, headerName,
                SENTINEL_SPOT, body == null ? "" : body);
    }

    static boolean isSentinel(String extracted) {
        return extracted == null
                || SENTINEL_SPOT.equals(extracted)
                || SENTINEL_SPOT_COMPACT.equals(extracted)
                || SENTINEL_EXTRACT.equals(extracted);
    }

    private static void runStep(ObtainEntry step) {
        if (step == null || step.iHttpRequestResponse == null || step.req == null) {
            return;
        }
        IHttpService legacyService = step.iHttpRequestResponse.getHttpService();
        if (legacyService == null || BurpExtender.api == null) {
            return;
        }
        boolean https = "https".equalsIgnoreCase(legacyService.getProtocol());
        HttpService service = HttpService.httpService(legacyService.getHost(), legacyService.getPort(), https);
        HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(step.req));
        String message = request.toString();
        for (ReplacementEntry replacement : copyStepReplacements(step)) {
            if (replacement == null || replacement.selectedString == null || replacement.selectedString.isEmpty()) {
                continue;
            }
            String value = extractionValue(replacement.extractionName);
            if (value == null) {
                value = "";
            }
            message = message.replace(replacement.selectedString, value);
        }
        HttpRequest prepared = message.equals(request.toString())
                ? request
                : HttpRequest.httpRequest(service, message);
        HttpRequestResponse sent = send(prepared, true);
        if (sent == null || sent.response() == null) {
            BurpExtender.log("ATOR obtain step " + step.getMsgID() + " returned no response");
            return;
        }
        String responseText = sent.response().toString();
        for (ExtractionEntry extraction : copyStepExtractions(step)) {
            storeExtraction(responseText, extraction);
        }
    }

    private static HttpRequestResponse send(HttpRequest request, boolean macro) {
        if (request == null || BurpExtender.api == null) {
            return null;
        }
        HttpRequest outgoing = macro ? request.withAddedHeader(AtorHttpHandler.MACRO_HEADER, "1") : request;
        AtorHttpHandler.enter();
        try {
            return BurpExtender.api.http().sendRequest(outgoing, RequestOptions.requestOptions()
                    .withHttpMode(HttpMode.AUTO)
                    .withResponseTimeout(60000));
        } finally {
            AtorHttpHandler.exit();
        }
    }

    static void storeExtraction(String responseText, ExtractionEntry extraction) {
        if (extraction == null) {
            return;
        }
        String start = extraction.startString == null ? "" : extraction.startString;
        String stop = extraction.stopString == null ? "" : extraction.stopString;
        String extracted = Extraction.extractData(responseText == null ? "" : responseText, start, stop, SENTINEL_EXTRACT);
        String name = extraction.getName() == null ? "" : extraction.getName();
        if (name.startsWith("jwt")) {
            String[] parts = name.split("_");
            if (parts.length > 1) {
                extracted = new DecodeToken(BurpExtender.callbacks).getTokenValue(extracted, parts[1]);
            }
        }
        try {
            if ("Decode".equals(extraction.isencode_decode)) {
                extracted = java.net.URLDecoder.decode(extracted, StandardCharsets.UTF_8);
            } else if ("Encode".equals(extraction.isencode_decode)) {
                extracted = java.net.URLEncoder.encode(extracted, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            BurpExtender.log("ATOR encode/decode failed for " + name + ": " + e.getMessage());
        }
        extraction.value = extracted;
    }

    private static HttpRequest replaceInSection(HttpRequest request, String where, String extracted, String value) {
        if ("URL".equals(where)) {
            String path = request.path();
            if (path != null && path.contains(extracted)) {
                return request.withPath(path.replace(extracted, value));
            }
            return request;
        }
        if ("BODY".equals(where)) {
            String body = request.bodyToString() == null ? "" : request.bodyToString();
            if (body.contains(extracted)) {
                return request.withBody(body.replace(extracted, value));
            }
            return request;
        }
        HttpRequest updated = request;
        boolean replaced = false;
        for (HttpHeader header : request.headers()) {
            String headerValue = header.value() == null ? "" : header.value();
            if (headerValue.contains(extracted)) {
                updated = updated.withUpdatedHeader(header.name(), headerValue.replace(extracted, value));
                replaced = true;
            }
        }
        if (!replaced) {
            String body = request.bodyToString() == null ? "" : request.bodyToString();
            if (body.contains(extracted)) {
                updated = request.withBody(body.replace(extracted, value));
            }
        }
        return updated;
    }

    private static boolean missingToken() {
        synchronized (ObtainPanel.extractionEntrylist) {
            if (ObtainPanel.extractionEntrylist.isEmpty()) {
                return false;
            }
            for (ExtractionEntry entry : ObtainPanel.extractionEntrylist) {
                if (entry.value == null || entry.value.isEmpty() || isSentinel(entry.value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String extractionValue(String name) {
        if (name == null) {
            return null;
        }
        synchronized (ObtainPanel.extractionEntrylist) {
            for (ExtractionEntry entry : ObtainPanel.extractionEntrylist) {
                if (name.equals(entry.getName())) {
                    return entry.value;
                }
            }
        }
        return null;
    }

    private static List<ReplaceEntry> copyReplaceRules() {
        synchronized (ReplacePanel.replaceEntrylist) {
            return new ArrayList<>(ReplacePanel.replaceEntrylist);
        }
    }

    private static List<ObtainEntry> copyObtainSteps() {
        synchronized (ObtainPanel.obtainEntrylist) {
            return new ArrayList<>(ObtainPanel.obtainEntrylist);
        }
    }

    private static List<ReplacementEntry> copyStepReplacements(ObtainEntry step) {
        synchronized (step.replacementlistNames) {
            return new ArrayList<>(step.replacementlistNames);
        }
    }

    private static List<ExtractionEntry> copyStepExtractions(ObtainEntry step) {
        synchronized (step.extractionlistNames) {
            return new ArrayList<>(step.extractionlistNames);
        }
    }

    private static void publishExtractionTable() {
        Runnable publish = () -> {
            if (ObtainPanel.extractionTableModel != null) {
                ObtainPanel.extractionTableModel.fireTableDataChanged();
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            publish.run();
        } else {
            SwingUtilities.invokeLater(publish);
        }
    }

    private static String contentTypeOf(HttpRequest request) {
        if (request == null || !request.hasHeader("Content-Type")) {
            return "";
        }
        String value = request.headerValue("Content-Type");
        return value == null ? "" : value.trim();
    }

    private static String selectedFallback(ReplaceEntry rule, String headers, String body, String urlText) {
        String selected = rule.selectedText;
        if (selected == null || selected.isEmpty()) {
            return SENTINEL_SPOT;
        }
        if ((headers != null && headers.contains(selected))
                || (body != null && body.contains(selected))
                || (urlText != null && urlText.contains(selected))) {
            return selected;
        }
        return SENTINEL_SPOT;
    }

    /**
     * HTTP/1 keeps the editor's bytes. Replacing inside that text matches the
     * ATOR preview. HTTP/2 stays on the structured header edit above.
     */
    private static HttpRequest replaceHttp1Raw(HttpRequest request, String extracted, String value) {
        if (request == null || extracted == null || extracted.isEmpty() || value == null) {
            return request;
        }
        String version = request.httpVersion() == null ? "" : request.httpVersion();
        if (version.toUpperCase().contains("HTTP/2")) {
            return request;
        }
        String raw = request.toString();
        if (!raw.contains(extracted) || extracted.equals(value)) {
            return request;
        }
        HttpService service = request.httpService();
        if (service == null) {
            return request;
        }
        return HttpRequest.httpRequest(service, raw.replace(extracted, value));
    }

    private static String headerSection(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        int split = raw.indexOf("\r\n\r\n");
        if (split >= 0) {
            return raw.substring(0, split);
        }
        split = raw.indexOf("\n\n");
        if (split >= 0) {
            return raw.substring(0, split);
        }
        return raw;
    }

    private static String safeUrl(HttpRequest request) {
        try {
            return request.method() + " " + request.url();
        } catch (Exception e) {
            return request.method() + " " + request.path();
        }
    }
}
