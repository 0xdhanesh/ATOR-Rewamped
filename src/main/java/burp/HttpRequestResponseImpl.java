package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class HttpRequestResponseImpl implements IHttpRequestResponse{
	
	byte[] request, response = null;
	String comment, highlight;
	IHttpService iHttpService;
	
	public HttpRequestResponseImpl(byte[] request, byte[] response, 
									String comment, String highlight, IHttpService iHttpService) {
		this.request = request;
		this.response = response;
		this.comment = comment;
		this.highlight = highlight;
		this.iHttpService = iHttpService;
	}
	
	@Override
	public byte[] getRequest() {
		return this.request;
	}

	@Override
	public void setRequest(byte[] message) {
		this.request = message;
	}

	@Override
	public byte[] getResponse() {
		return this.response;
	}

	@Override
	public void setResponse(byte[] message) {
		this.response = message;
	}

	@Override
	public String getComment() {
		return this.comment;
	}

	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	@Override
	public String getHighlight() {
		return this.highlight;
	}

	@Override
	public void setHighlight(String color) {
		this.highlight = color;
	}

	@Override
	public IHttpService getHttpService() {
		return this.iHttpService;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.iHttpService = httpService;
	}

	@Override
	public String getHost() {
		return iHttpService == null ? null : iHttpService.getHost();
	}

	@Override
	public int getPort() {
		return iHttpService == null ? 0 : iHttpService.getPort();
	}

	@Override
	public String getProtocol() {
		return iHttpService == null ? null : iHttpService.getProtocol();
	}

	@Override
	public void setHost(String host) {
		int port = getPort();
		String protocol = getProtocol() == null ? "http" : getProtocol();
		this.iHttpService = new IHttpServiceImpl(host, port, protocol);
	}

	@Override
	public void setPort(int port) {
		String host = getHost() == null ? "" : getHost();
		String protocol = getProtocol() == null ? "http" : getProtocol();
		this.iHttpService = new IHttpServiceImpl(host, port, protocol);
	}

	@Override
	public void setProtocol(String protocol) {
		String host = getHost() == null ? "" : getHost();
		this.iHttpService = new IHttpServiceImpl(host, getPort(), protocol);
	}

	@Override
	public URL getUrl() {
		if (iHttpService == null || iHttpService.getHost() == null) {
			return null;
		}
		String path = "/";
		if (request != null && request.length > 0) {
			String text = new String(request, StandardCharsets.ISO_8859_1);
			int lineEnd = text.indexOf('\n');
			String first = (lineEnd >= 0 ? text.substring(0, lineEnd) : text).trim();
			String[] parts = first.split(" ");
			if (parts.length >= 2 && parts[1].startsWith("/")) {
				path = parts[1];
			}
		}
		String protocol = iHttpService.getProtocol() == null ? "http" : iHttpService.getProtocol();
		try {
			return new URL(protocol + "://" + iHttpService.getHost() + ":" + iHttpService.getPort() + path);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	@Override
	public short getStatusCode() {
		if (response == null || response.length < 12) {
			return 0;
		}
		int length = Math.min(response.length, 24);
		String start = new String(response, 0, length, StandardCharsets.ISO_8859_1);
		String[] parts = start.split(" ");
		if (parts.length < 2) {
			return 0;
		}
		try {
			return Short.parseShort(parts[1]);
		} catch (NumberFormatException e) {
			return 0;
		}
	}

}
