package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;


public class CheckCondition {
	public static boolean matches(HttpResponse response) {
		if (response == null || PreviewPanel.conditionDetails == null) {
			return false;
		}
		String conditionDetailsText = PreviewPanel.conditionDetails.getText();
		if (conditionDetailsText == null || conditionDetailsText.isBlank()) {
			return false;
		}
		String[] conditionList = conditionDetailsText.split(" ");
		String evaluatedCondition = "";
		for (String condition : conditionList) {
			if (condition.isEmpty()) {
				continue;
			}
			for (ErrorEntry err : ErrorPanel.errorEntrylist) {
				if (condition.equals("AND")) {
					evaluatedCondition += " && ";
					break;
				} else if (condition.equals("OR")) {
					evaluatedCondition += " || ";
					break;
				}
				if (err.getConditionname().equals(condition)) {
					evaluatedCondition += Boolean.toString(checkCondition(err.getCategory(), err.getValue(), response));
					break;
				}
			}
		}
		try {
			return evaluateCondition(evaluatedCondition);
		} catch (Exception e) {
			BurpExtender.log("Exception while checking the error condition " + e.getMessage());
			return false;
		}
	}

	public static boolean evaluteErrorCondition(IHttpRequestResponse iHttpRequestResponse) {
		if (iHttpRequestResponse == null || iHttpRequestResponse.getResponse() == null || PreviewPanel.conditionDetails == null) {
			return false;
		}
		String conditionDetailsText = PreviewPanel.conditionDetails.getText();
		if (conditionDetailsText == null || conditionDetailsText.isBlank()) {
			return false;
		}
		String[] conditionList = conditionDetailsText.split(" ");
		String evaluatedCondition = "";
		for(String condition:conditionList) {
			for(ErrorEntry err: ErrorPanel.errorEntrylist) {
				if(condition.equals("AND")) {
					evaluatedCondition += " && ";
					break;
				}
				else if(condition.equals("OR")) {
					evaluatedCondition += " || ";
					break;
				}
				
				if(err.getConditionname().equals(condition)) {
					String category = err.getCategory();
					String value = err.getValue();
					evaluatedCondition += Boolean.toString(checkCondition(category, value, iHttpRequestResponse));
					break;
				}
			}
			
		}
		try {
			return evaluateCondition(evaluatedCondition);

        } catch (Exception e) {
        	BurpExtender.log("Exception while checking the error condition " + e.getMessage());
        	return false;
        }
		
	}
	
	public static boolean evaluateCondition(String value) {
		
		String[] splittedValue = value.split(" ");
		boolean checkFinal;
		checkFinal = Boolean.valueOf(splittedValue[0]);
		for(int i=2; i < splittedValue.length; i=i+2) {
			boolean operand2 = Boolean.valueOf(splittedValue[i]);
			checkFinal = calculateCondition(checkFinal, operand2, splittedValue[i-1]);
		}
		
		return checkFinal;
		
	}
	
	public static boolean calculateCondition(boolean operand1, boolean operand2, String condition) {
		switch(condition) {
		case "&&":
			return operand1 && operand2;
		case "||":
			return operand1 || operand2;
		}
		return false;
		
	}
	
	public static boolean checkCondition(String category, String value, HttpResponse response) {
		if (response == null || value == null) {
			return false;
		}
		if (category.equals("Status Code")) {
			return String.valueOf(response.statusCode()).equals(value);
		}
		if (category.equals("Body")) {
			String body = response.bodyToString();
			return body != null && body.contains(value);
		}
		if (category.equals("Header")) {
			StringBuilder headerText = new StringBuilder();
			for (HttpHeader header : response.headers()) {
				headerText.append(header.name()).append(": ").append(header.value()).append(' ');
			}
			return headerText.toString().contains(value);
		}
		return false;
	}

	public static boolean checkCondition(String category, String value, IHttpRequestResponse iHttpRequestResponse) {
		if(category.equals("Status Code")) {
			return checkStatusCode(value, iHttpRequestResponse);
		}
		else if(category.equals("Body")) {
			return checkBody(value, iHttpRequestResponse);
		}
		else if(category.equals("Header")) {
			return checkHedaer(value, iHttpRequestResponse);
		}
		return false;
	}
	
	public static boolean checkStatusCode(String statusCode, IHttpRequestResponse iHttpRequestResponse) {
		IResponseInfo iResponseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(iHttpRequestResponse.getResponse());
		short value = iResponseInfo.getStatusCode();
		if(String.valueOf(value).equals(statusCode)) {
			return true;
		}
		return false;
		
	}
	
	public static boolean checkBody(String body, IHttpRequestResponse iHttpRequestResponse) {
		IResponseInfo iResponseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(iHttpRequestResponse.getResponse());
		
		String response = BurpExtender.callbacks.getHelpers().bytesToString(iHttpRequestResponse.getResponse());
		response = response.substring(iResponseInfo.getBodyOffset());
		if(response.indexOf(body) != -1) {
			return true;
		}
		return false;
		
	}
	
	public static boolean checkHedaer(String headerStringValue, IHttpRequestResponse iHttpRequestResponse) {
		IResponseInfo iResponseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(iHttpRequestResponse.getResponse());
		
		List<String> headers =
				iResponseInfo.getHeaders();
		StringBuffer headerStringBuffer = new StringBuffer();
	      
	      for (String hd : headers) {
	    	  headerStringBuffer.append(hd);
	    	  headerStringBuffer.append(" ");
	      }
	    
	      
		String headerString = headerStringBuffer.toString();
		if(headerString.indexOf(headerStringValue) != -1) {
			return true;
		}
		return false;
		
	}
}
