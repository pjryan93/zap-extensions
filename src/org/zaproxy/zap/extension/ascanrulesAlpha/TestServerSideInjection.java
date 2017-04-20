package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.text.MessageFormat;
import java.util.List;
import java.util.Set;
import java.util.Random;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;



public class TestServerSideTemplateInjection extends AbstractAppParamPlugin{

	//private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");
	private static final int PLUGIN_ID = 90036;
 	private static final String MESSAGE_PREFIX = "ascanalpha.testserversidetemplateinjection."; 
	private static Logger log = Logger.getLogger(TestServerSideTemplateInjection.class);
	  
	private Random rnd = new Random();

	private String firstNumber = String.valueOf(rnd.nextInt(500));
	private String secondNumber = String.valueOf(rnd.nextInt(500));
	private int result = Integer.parseInt(firstNumber) * Integer.parseInt(secondNumber);
	private String vulnerableResult = String.valueOf(result);
    
    private String payload = String.valueOf(firstNumber) + "*" + String.valueOf(secondNumber);

	private String[] PAYLOADS = {
	 	"str(" + payload + ")",//python str(7*7)
	 	"{{python}} print "+ payload + "{{/python}}",//{python {python}} print 7*7{{/python}}
	 	"{{" + payload + "}}", //Flask,Jinja2,tornado  //twig {{7*7}}
	 	"\"#{" + payload + "}\"", //ruby "#{7*7}"
	 	"#{" + payload + "}", // #{7*7}
	 	"{php} echo " + payload + ";{/php}", // Unsandboxed Smarty" {php} echo 7*7;{/php}"
	 	"{{" + firstNumber + "*" + "'" + secondNumber + "'}}", //twig, jinja2 {{7*'7'}}
	 	"${" + payload + "}", //${7*7}
	 	payload //7 * 7
	 	//"${'" + firstNumber + "'.join('" + secondNumber + "')}", //${'1234'.join('56789')}
    };

   	private  String[] EXECUTEDPAYLOAD = {
   		vulnerableResult,
   		vulnerableResult,
   		vulnerableResult,
   		vulnerableResult,
   		vulnerableResult,
   		vulnerableResult,
	 	vulnerableResult,
	 	vulnerableResult,
	 	vulnerableResult
	 	//"123456789",
    };
    
    private static final String[] FUNCTIONPAYLOADS = {
    	//https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/
    	"{{ ''.__class__.__mro__[0].__subclasses__() }}", //flask jijna
    	"{{ ''.__class__.__mro__[1].__subclasses__() }}" //flask jinja

    };

	@Override
	public int getId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is https://github.com/zaproxy/zaproxy/blob/develop/src/doc/scanners.md
		 */
		return PLUGIN_ID;
	}

	@Override
	public String getName() {

		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}
	
	@Override
	public String getDescription() {

		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {

		return Constant.messages.getString(MESSAGE_PREFIX + "soln"); 
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public void init() {

	}

	@Override
	public void scan(HttpMessage msg, String param, String value) {

		try {
			if (!Constant.isDevBuild()) {
				
				return;
			}

			String attack = null;
			HttpMessage normalMsg = getNewMsg();

			try{

				sendAndReceive(msg);

			}catch(Exception e){

			}

			for (int i = 0; i < PAYLOADS.length; i++){

				msg = getNewMsg();
				attack = PAYLOADS[i];

				//if (log.isDebugEnabled()) {
                	log.debug("Testing [" + param + "] = [" + attack + "]");
            	//}
            	System.out.println("Testing [" + param + "] = [" + attack + "]");
            	System.out.println("[" + attack + "]" + " = " +EXECUTEDPAYLOAD[i] );
				setParameter(msg, param, attack);

				try{
					sendAndReceive(msg);
				} 
				catch(Exception e){

					if (log.isDebugEnabled()){
						continue;
					}
				}

				if (isVulnerable(msg, attack, EXECUTEDPAYLOAD[i])) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, attack, null, msg);
                }

			}
			
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}	
	}
	private boolean isVulnerable(HttpMessage msg, String attack, String executedResponse){
        if(msg.getResponseBody().toString().contains(executedResponse)){
        	return true;
        }

        return false;
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		// The CWE id
		return 96;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 20;
	}

}