package burp;
import javax.swing.*;
import java.awt.*;
import java.util.List;

public class Utils {
	static Color BURP_ORANGE = new Color(255, 128, 0);
    public static void blinkTab(final ITab iTab){
        JTabbedPane tp = (JTabbedPane) iTab.getUiComponent().getParent();
        int tabidx = getTabIndex(iTab);
        tp.setBackgroundAt(tabidx, BURP_ORANGE);

        // unblink tab in 4 seconds
        Thread t1 = new Thread(new Runnable() {
            public void run()
            {
                try {
                    Thread.sleep(4000);

                    unblinkTab(iTab);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }});
        t1.start();
    }

    public static void unblinkTab(ITab iTab){
        JTabbedPane tp = (JTabbedPane) iTab.getUiComponent().getParent();
        int tabidx = getTabIndex(iTab);
        tp.setBackgroundAt(tabidx, Color.BLACK);
    }

    private static int getTabIndex(ITab iTab) {
        JTabbedPane mom = (JTabbedPane) iTab.getUiComponent().getParent();;
        for(int i = 0; i < mom.getTabCount(); ++i) {
            if(iTab.getTabCaption().equals(mom.getTitleAt(i))) {
                return i;
            }
        }
        return -1;
    }
    
    public static byte[] checkContentLength(byte[] request, IExtensionHelpers helpers) {
		if (request == null || helpers == null) {
			return request;
		}
		IRequestInfo iRequestInfo = helpers.analyzeRequest(request);
		int offset = iRequestInfo.getBodyOffset();
		byte[] body = java.util.Arrays.copyOfRange(request, Math.min(offset, request.length), request.length);
		List<String> headers = new java.util.ArrayList<String>(iRequestInfo.getHeaders());
		boolean found = false;
		for (int i = 0; i < headers.size(); i++) {
			String header = headers.get(i);
			int colon = header.indexOf(':');
			if (colon > 0 && header.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
				headers.set(i, "Content-Length: " + body.length);
				found = true;
				break;
			}
		}
		if (!found && body.length > 0) {
			headers.add("Content-Length: " + body.length);
		}
		return helpers.buildHttpMessage(headers, body);
	}
    
    public static String findheader(String request, String header) {
    	String text = null;
    	try {
    		String[] requestList = request.split("\\n");
    		 for(int i = 0; i < requestList.length; i++)
 	        	{
 	        	boolean matchedText = requestList[i].contains(header); 
	            if(matchedText) {
	            	String[] matchedLine =requestList[i].split(header);
	            	text = matchedLine[1].strip().toString();	
 	        	}
 	        }
    	}
    	catch(Exception e) {
    		BurpExtender.callbacks.printOutput("Exception in findNextStringBeforeStopString"+ e.getMessage());
    	}
    	return text;
    }
}
