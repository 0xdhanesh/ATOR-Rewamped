# Authentication Token Obtain and Replace (ATOR)

ATOR is a Burp Suite extension that obtains tokens from a recorded macro and replaces them in later requests. It covers access and refresh tokens in headers, cookies, the URL, and XML, JSON, or form bodies.

Version 2.4.1 keeps the same four-step configuration UI and adds a Montoya HTTP path that stays valid on HTTP/2. It also exposes a small command plane that burp-mcp can call.

The original idea comes from [ExtendedMacro](https://github.com/FrUh/ExtendedMacro).

## What 2.4.1 changes

Earlier builds rewrote the raw request bytes from a legacy HTTP listener. On Burp 2026.8 that rewrite dropped HTTP/2 framing, so a replaced request left the tool.

2.4.1 registers two Montoya hooks instead:

| Hook | Class | What it does |
| --- | --- | --- |
| HTTP handler | `AtorHttpHandler` | Applies stored tokens on the way out. On an error response, refreshes the token and retries. |
| Session handling action | `AtorSessionAction` | Action name `ATOR`. Session rules, including rules written by burp-mcp `set_project_options`, call it before the request is sent. |

Message edits go through Montoya `withPath`, `withUpdatedHeader`, and `withBody`. HTTP/2 messages stay structured. HTTP/1 messages can still fall back to a raw text replace when the structured edit does not match the bytes the preview shows.

Other behavior in this build:

- Header matching is case-insensitive. HTTP/2 sends lowercase header names.
- `Content-Length` is updated from the body bytes, and a missing length is added when the body is not empty.
- JWT extraction names that start with `jwt` still split on `_` and read a claim. Padding is added before the Base64-url decode, and a missing claim returns the original token.
- Obtain and refresh share one lock (60 second wait) so two tools do not run the login macro at the same time. Macro requests carry `X-ATOR-Macro: 1` and are not processed again.
- Preview mode turns the live handler and the session action off. Use Preview to inspect a replacement before it rewrites traffic.
- The Settings tab adds **Extensions (burp-mcp)** and **Burp AI**. Both default to on, with Repeater, Intruder, Scanner, Sequencer, and Proxy. **InScope** defaults to off. The Spider checkbox is still on the tab and is not read by the Montoya handler.

The extension logs this line when both the legacy and Montoya entry points have run:

```text
ATOR v2.4.1 loaded for Burp 2026.8 (Montoya HTTP handler, HTTP/2 safe).
```

## How a request is handled

1. If any extraction value is missing, or is an extraction sentinel (`Ext ERR on SPOT`, `ExtERRonSPOT`, `EXTRACTION_ERROR`), ATOR runs the obtain macro.
2. Each replacement rule locates the current token (URL, JSON or multipart body, or header) and writes the stored value into that section.
3. When the response matches the configured error condition, ATOR runs the obtain macro again, rebuilds the original request, sends it, and returns that response to the tool. The message note is `ATOR refreshed this response`.

The handler skips the request when Preview is on, the tool checkbox is off, or **InScope** is on and the request is out of scope. A handler exception is logged and the original message continues.

The session action only does steps 1 and 2. The error-triggered retry stays on the HTTP handler.

## burp-mcp commands

burp-mcp has no separate ATOR invoke API. Send a normal request with `send_http1_request` or `send_http2_request` and add the header `X-ATOR-Command`. The handler accepts that header only from **Extensions**, **Burp AI**, and **Repeater**, so a proxied browser cannot call it. The request is not forwarded.

| Command | Body | Result |
| --- | --- | --- |
| `status` | empty | JSON snapshot. Extraction values are included. |
| `refresh` | empty | Runs the obtain macro, then the same snapshot as `status`. |
| `export` | empty | `{ "ok": true, "action": "export", "config": "<ATOR export JSON>" }`. `config` is the same document the Settings **Export ATOR** button writes. |
| `import` | ATOR export JSON | Loads error conditions, obtain steps, and replacement rules on the Swing thread. The response is a `status` snapshot without extraction values. |

Unknown commands return HTTP 400. A failed command returns HTTP 500 with `{ "ok": false, "error": "..." }`. Responses use `Content-Type: application/json` and `X-ATOR: 1`.

`status` fields:

- `extension`, `version` (`2.4.1`), `sessionHandlingAction` (`ATOR`)
- `preview`, `inScopeOnly`, `trigger` (the condition expression from Preview)
- `tools`: Repeater, Intruder, Scanner, Sequencer, Proxy, Extensions, Burp AI, each with `enabled`
- `extractions`: `name`, `present`, `length`, and `value` when `present` is true
- `obtainSteps`, `replacements`, `errorConditions`
- `commandHeader`, `commands`

Example status call. The host is unused because the request is answered inside the extension:

```http
GET /ator HTTP/1.1
Host: ator.local
X-ATOR-Command: status

```

Example import. The body is the export document, not a wrapper:

```http
POST /ator HTTP/1.1
Host: ator.local
X-ATOR-Command: import
Content-Type: application/json

{"errorCondition":{},"obtainToken":{},"errorConditionReplacement":{}}
```

**Extensions (burp-mcp)** must stay enabled for `send_http1_request` and `send_http2_request` to receive token replacement. The command header itself is accepted from Extensions even when you only want `status` or `export`.

To have session rules call ATOR, add a session handling rule whose action is `ATOR`. burp-mcp `set_project_options` can write that rule. The action obtains missing tokens and applies replacement rules. It does not perform the error-triggered retry.

## Build

Requirements:

- JDK 17 (the compiler `release` is 17)
- Maven
- Burp Suite 2026.8. The compile dependency is Montoya API `2026.7`, scope `provided`, so it is not packed into the jar.

```bash
mvn clean package
```

Load the jar with dependencies from `target/` in **Extensions > Add > Java**. `BappManifest.bmf` names the extension **Authentication Token Obtain and Replace**, screen version `2.4.1`, and lists the BApp entry point as `bin/ATOR-v2.4.1.jar`. Rebuild before relying on the copy under `bin/`.

`mvn clean install` matches the manifest `BuildCommand` and also installs the artifact locally.

## Configure ATOR

The suite tab is **ATOR v2.4.1**. It has two sections: **ATOR Configuration** and **Settings**.

Configuration has four steps:

1. **Error Condition.** The response that means the token is dead.
2. **Obtain Token.** The macro that logs in and extracts values.
3. **Error Condition Replacement.** Where those values are written on the next request.
4. **Preview.** Dry-run the replacement. While Preview is enabled, live traffic is not modified.

Add messages from Proxy history with **Send to ATOR v2.4.1**, then choose **1. Error Condition** or **2. ATOR Macro (Obtain Token)**.

### Error condition

Each condition has a name, a kind, and a value. The kinds are **Status Code** (exact match, for example `401`), **Body** (the body contains the text), and **Header** (the header block contains the text).

On the replacement step, pick one named condition, or combine several with **AND** or **OR**. Preview shows the expression, for example `Expired AND Unauthorized`. The live handler splits that text on spaces, evaluates each name, and applies the operators left to right. A blank expression does not match.

### Replacement

Name the extraction (for example `token`). The replacement rule uses the same region and writes the extraction value back.

For a Bearer header:

- Match: `Authorization: Bearer \w*`
- Replacement area: `Authorization: Bearer token`

One error condition can have several replacement rules. JSON and `multipart/form-data` bodies use the JSON body extractor. Other bodies and headers use the spot extractor. URL rules read the request line.

Extraction names can request URL encode or decode. A name that starts with `jwt`, such as `jwt_sub`, extracts the token and then reads that claim from the payload.

### Settings

- Tool checkboxes choose which Burp tools the live handler updates. **All/None** toggles every checkbox, including **InScope**.
- **InScope** limits replacement and refresh to in-scope requests.
- **Export ATOR** and **Import ATOR** read and write the same JSON that the `export` and `import` commands use.

## Walkthrough with Tiredful

Record traffic from [Tiredful-API](https://github.com/payatu/Tiredful-API) through Burp, then confirm ATOR replaces the token.

1. Generate a token at `http://<HOST:PORT>/handle-user-token/`.
2. Call `http://<HOST:PORT>/api/v1/exams/MQ==/` with `Authorization: Bearer <token>`.
3. Load the ATOR jar.
4. Send `/handle-user-token/` to **ATOR Macro (Obtain Token)**. Select the `access_token` value and name the extraction `token`. This app needs one request. A macro can contain more than one.
5. On the replacement step set:
   - Error condition: status code `401`
   - Pattern: `Authorization: Bearer \w*`
   - Replacement area: `Authorization: Bearer token`
6. Send the exams request from Repeater with a bad bearer token.
   - The response is 401, so ATOR runs the macro, extracts `access_token`, and retries.
   - Repeater shows `200`. The note on the response is `ATOR refreshed this response`.
7. Send it again. The stored token is still valid, so ATOR does not run the macro.

Watch the obtain and retry traffic in Logger++ or the extension output. A second in-flight refresh waits on the obtain lock instead of logging in twice.

## Version

2.4.1

## Authors

Initial work: [ExtendedMacro](https://github.com/FrUh/ExtendedMacro).

Synopsys.

## License

Synopsys releases this software under the MIT license.
