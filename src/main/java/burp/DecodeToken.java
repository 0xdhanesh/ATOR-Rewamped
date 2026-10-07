package burp;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class DecodeToken {
	DecodeToken(IBurpExtenderCallbacks callbacks) {
	}

	public String getTokenValue(String token, String bodykey) {
		try {
			String[] splitString = token.split("\\.");
			String payload = splitString[1];
			int pad = (4 - (payload.length() % 4)) % 4;
			payload = payload + "====".substring(0, pad);
			String json = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
			JSONObject jsonObj = new JSONObject(json);
			Object value = jsonObj.opt(bodykey);
			return value == null ? token : String.valueOf(value);
		}
		catch (Exception e) {
			return token;
		}
	}
}
