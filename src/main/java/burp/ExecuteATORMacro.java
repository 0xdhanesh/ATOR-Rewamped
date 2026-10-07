package burp;


public class ExecuteATORMacro {
	IBurpExtenderCallbacks callbacks;
	public ExecuteATORMacro(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}
	
	public void executeATORMacro() {
		try {
			AtorEngine.runObtain();
		}
		catch(Exception e) {
			BurpExtender.log("Exception while executing ATOR " + e.getMessage());
		}
	}
	
	
	public String getExtractionEntry(String name) {
		String extractedString = "";
		for(ExtractionEntry extractionEntry: ObtainPanel.extractionEntrylist) {
			// Do extraction if any
			if(extractionEntry.getName().equals(name)) {
				extractedString = extractionEntry.value;
				break;
			}
		}
		return extractedString;
	}
	
	
	public void setExtractionEntry(String response, ExtractionEntry extractionEntry) {
		String startString = extractionEntry.startString;
		String stopString = extractionEntry.stopString;
		String extractedString = Extraction.extractData(response, startString, stopString, "EXTRACTION_ERROR");
		String extractionname = extractionEntry.getName();
		if(extractionname.startsWith("jwt")) {
			DecodeToken decodeToken = new DecodeToken(callbacks);
			String[] extractedvalue = extractionname.split("_");
			if(extractedvalue.length > 1) {
				extractedString = decodeToken.getTokenValue(extractedString, extractedvalue[1]);
			}
		}
		try {
			if(extractionEntry.isencode_decode.equals("Decode")) {
				extractedString = java.net.URLDecoder.decode(extractedString, "UTF-8");
			}
			else if(extractionEntry.isencode_decode.equals("Encode")) {
				extractedString = java.net.URLEncoder.encode(extractedString, "UTF-8");
			}
		}
		catch (Exception e) {
			BurpExtender.callbacks.printOutput("Exception while performing encoding/decoding " + e);
		}
		extractionEntry.value = extractedString;
	}
	
	public void makeHttpCall(IHttpService httpService, byte[] request, ObtainEntry obtainEntry) {
		try {
			String response = makeCall(httpService, request);
			for(ExtractionEntry extractionEntry: obtainEntry.extractionlistNames) {
				// Do extraction if any
				setExtractionEntry(response, extractionEntry);
			}
		}
		catch (Exception e) {
			BurpExtender.callbacks.printOutput("Exception in makeHttpCall " + e.getMessage());
		}
	}
	
	public String makeCall(IHttpService iHttpService, byte[] requestbytes) {
		String response = null;
		try {
			byte[] updatedRequest = Utils.checkContentLength(requestbytes, callbacks.getHelpers());
			IHttpRequestResponse sent = AtorEngine.sendLegacy(iHttpService, updatedRequest);
			response = callbacks.getHelpers().bytesToString(sent.getResponse());
	    	return response;
		}
		catch (Exception e) {
			BurpExtender.log("Exception in makeCall " + e.getMessage());
			return response;
		}
	}
	
	
	public static String replaceOnRequest(IHttpRequestResponse iHttpRequestResponse) {
		String requestmsg = BurpExtender.callbacks.getHelpers().bytesToString(iHttpRequestResponse.getRequest());
		int offset = BurpExtender.callbacks.getHelpers().analyzeRequest(iHttpRequestResponse).getBodyOffset();
		String urlText = requestmsg.split("\n")[0];
		String headers = requestmsg.substring(0, offset);
    	String bodyText = requestmsg.substring(offset);
		String contentType = contentTypeFrom(headers);
		for(ReplaceEntry rep: ReplacePanel.replaceEntrylist) {
			String extracted = AtorEngine.findCurrentValue(rep, urlText, headers, bodyText, contentType);
			String extractionName = rep.getextractionName();

			for(ExtractionEntry extractionEntry: ObtainPanel.extractionEntrylist) {
				if(extractionEntry.getName().equals(extractionName)) {
					String value = extractionEntry.value;
					if (value != null && !AtorEngine.isSentinel(extracted) && !extracted.isEmpty()) {
						value = Extraction.removeemptyCharacter(value);
						try {
							requestmsg = requestmsg.replace(extracted, value);
						}
						catch (Exception e) {
							BurpExtender.log("Exception in value replacement " + e.getMessage());
						}
					}
					break;
				}
			}
		}
		return requestmsg;
	}

	private static String contentTypeFrom(String headers) {
		if (headers == null) {
			return "";
		}
		for (String line : headers.split("\n")) {
			if (line.toLowerCase().startsWith("content-type:")) {
				return line.substring(line.indexOf(':') + 1).trim();
			}
		}
		return BurpExtender.bodyContentType == null ? "" : BurpExtender.bodyContentType;
	}
}
