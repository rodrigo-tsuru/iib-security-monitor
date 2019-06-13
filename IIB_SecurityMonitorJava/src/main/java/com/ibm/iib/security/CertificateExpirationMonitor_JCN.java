package com.ibm.iib.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import com.ibm.broker.config.proxy.BrokerProxy;
import com.ibm.broker.config.proxy.ExecutionGroupProxy;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.javastartparameters.JavaStartParameters;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbJSON;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;


/***
 * 
 * @author Rodrigo Tsuru <caixapostal@gmail.com>
 */
public class CertificateExpirationMonitor_JCN extends MbJavaComputeNode {

	private static int CERTIFICATE_EXPIRATION_INTERVAL = 90;
	
	private final static Logger LOGGER = Logger.getLogger(CertificateExpirationMonitor_JCN.class.getName());
	
	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		MbOutputTerminal alt = getOutputTerminal("alternate");

		MbMessage inMessage = inAssembly.getMessage();

		// create new empty message
		MbMessage outMessage = new MbMessage();
		MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly,
				outMessage);
		
		Calendar expirationCal = Calendar.getInstance();
		expirationCal.add(Calendar.DATE, CERTIFICATE_EXPIRATION_INTERVAL);
		final Date CHECK_DATE = expirationCal.getTime();
		
		BrokerProxy b = null;
		try {
			// optionally copy message headers
			copyMessageHeaders(inMessage, outMessage);
			// ----------------------------------------------------------
			b = BrokerProxy.getLocalInstance();
			
			if(b.hasBeenPopulatedByBroker(true)) {
				
			} else {
				throw new RuntimeException("Cannot communicate with local Integration Node");
			}
			
			List<SecurityError> seList = new ArrayList<SecurityError>();
			
			//TODO: check IIB's JRE cacerts file
			
			
			// @see https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ab60250_.htm
			// Verifies node's keystore and trust stores used by request nodes (ex: HTTPRequest, SOAPRequest)
			String ksFile = b.getRegistryProperty("BrokerRegistry/brokerKeystoreFile");
			String ksPass = b.getRegistryProperty("BrokerRegistry/brokerKeystorePass");
			String ksType = b.getRegistryProperty("BrokerRegistry/brokerKeystoreType");
			
			if(ksFile.isEmpty())
				LOGGER.finest("Broker Keystore is not set");
			else
				seList.addAll(validateKeystoreContent(ksFile,ksPass,ksType,CHECK_DATE));
			
			String tsFile = b.getRegistryProperty("BrokerRegistry/brokerTruststoreFile");
			String tsPass = b.getRegistryProperty("BrokerRegistry/brokerTruststorePass");
			String tsType = b.getRegistryProperty("BrokerRegistry/brokerTruststoreType");
			
			if(tsFile.isEmpty())
				LOGGER.finest("Broker Truststore is not set");
			else
				seList.addAll(validateKeystoreContent(tsFile,tsPass,tsType,CHECK_DATE));
			
			// Verifies node's keystore and trust stores used by input nodes (ex: HTTPInput, SOAPInput)
			String HTTPS_ksFile = b.getHTTPListenerProperty("HTTPSConnector/keystoreFile");
			String HTTPS_ksPass = b.getHTTPListenerProperty("HTTPSConnector/keystorePass");
			String HTTPS_ksType = b.getHTTPListenerProperty("HTTPSConnector/keystoreType");
			
			if(HTTPS_ksFile.isEmpty())
				LOGGER.finest("Broker HTTPSConnector Keystore is not set");
			else
				seList.addAll(validateKeystoreContent(HTTPS_ksFile,HTTPS_ksPass,HTTPS_ksType,CHECK_DATE));
			
			String HTTPS_tsFile = b.getHTTPListenerProperty("HTTPSConnector/truststoreFile");
			String HTTPS_tsPass = b.getHTTPListenerProperty("HTTPSConnector/truststorePass");
			String HTTPS_tsType = b.getHTTPListenerProperty("HTTPSConnector/truststoreType");
			
			if(tsFile.isEmpty())
				LOGGER.finest("Broker Truststore is not set");
			else
				seList.addAll(validateKeystoreContent(HTTPS_tsFile,HTTPS_tsPass,HTTPS_tsType,CHECK_DATE));
			
			//TODO: check CRL?
			
			Enumeration<ExecutionGroupProxy> egs = b.getExecutionGroups(null);
			
			while(egs.hasMoreElements()) {
				
				// @see https://www.ibm.com/support/knowledgecenter/pt-br/SSMKHH_10.0.0/com.ibm.etools.mft.doc/ac56640_.htm
				
				// Verifies EG's keystore and trust stores used by request nodes (ex: HTTPRequest, SOAPRequest)
				ExecutionGroupProxy eg = egs.nextElement();
				String egKsFile = eg.getRuntimeProperty("ComIbmJVMManager/keystoreFile");
				String egKsPass = eg.getRuntimeProperty("ComIbmJVMManager/keystorePass");
				String egKsType = eg.getRuntimeProperty("ComIbmJVMManager/keystoreType");
				
				if(egKsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " Keystore is not set");
				else
					seList.addAll(validateKeystoreContent(egKsFile,egKsPass,egKsType,CHECK_DATE));
				
				String egTsFile = eg.getRuntimeProperty("ComIbmJVMManager/truststoreFile");
				String egTsPass = eg.getRuntimeProperty("ComIbmJVMManager/truststorePass");
				String egTsType = eg.getRuntimeProperty("ComIbmJVMManager/truststoreType");
				
				
				if(egTsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " Truststore is not set");
				else
					seList.addAll(validateKeystoreContent(egTsFile,egTsPass,egTsType,CHECK_DATE));
				
				// Verifies EG's keystore and trust stores used by input nodes (ex: HTTPInput, SOAPInput)
				String egHTTPS_KsFile = eg.getRuntimeProperty("HTTPSConnector/keystoreFile");
				String egHTTPS_KsPass = eg.getRuntimeProperty("HTTPSConnector/keystorePass");
				String egHTTPS_KsType = eg.getRuntimeProperty("HTTPSConnector/keystoreType");
				
				if(egHTTPS_KsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " HTTPSConnector Keystore is not set");
				else
					seList.addAll(validateKeystoreContent(egHTTPS_KsFile,egHTTPS_KsPass,egHTTPS_KsType,CHECK_DATE));
				
				String egHTTPS_TsFile = eg.getRuntimeProperty("HTTPSConnector/truststoreFile");
				String egHTTPS_TsPass = eg.getRuntimeProperty("HTTPSConnector/truststorePass");
				String egHTTPS_TsType = eg.getRuntimeProperty("HTTPSConnector/truststoreType");
				
				
				if(egHTTPS_TsFile.isEmpty())
					LOGGER.finest("EG " + eg.getName() + " HTTPSConnector Truststore is not set");
				else
					seList.addAll(validateKeystoreContent(egHTTPS_TsFile,egHTTPS_TsPass,egHTTPS_TsType,CHECK_DATE));
				
			}
			
			// Generate result message
			
			MbElement data = outMessage.getRootElement()
			.createElementAsLastChild(MbJSON.ROOT_ELEMENT_NAME)
			.createElementAsLastChild(MbElement.TYPE_NAME,"Data",null);
			
			data.createElementAsLastChild(MbElement.TYPE_NAME,"summary",null)
			.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"errorCount",seList.size());
			
			MbElement errors = data
					.createElementAsLastChild(MbJSON.ARRAY,"errors",null);
				
			for (SecurityError securityError : seList) {
				MbElement item = errors
					.createElementAsLastChild(MbJSON.OBJECT,MbJSON.ARRAY_ITEM_NAME,null);
				
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"message",securityError.getMessage());
				item.createElementAsLastChild(MbElement.TYPE_NAME_VALUE,"ref",securityError.getRef());
				
			}

			
			out.propagate(outAssembly);

			// End of user code
			// ----------------------------------------------------------
		} catch (MbException e) {
			// Re-throw to allow Broker handling of MbException
			throw e;
		} catch (RuntimeException e) {
			// Re-throw to allow Broker handling of RuntimeException
			throw e;
		} catch (Exception e) {
			// Consider replacing Exception with type(s) thrown by user code
			// Example handling ensures all exceptions are re-thrown to be handled in the flow
			throw new MbUserException(this, "evaluate()", "", "", e.toString(),
					null);
		} finally {
			if(b!=null) b.disconnect();
			
			outMessage.clearMessage(true);
		}
		// The following should only be changed
		// if not propagating message to the 'out' terminal
		
	}

	private List<SecurityError> validateKeystoreContent(String ksFile, String ksPass, String ksType, Date testDate) {
		
		List<SecurityError> list = new ArrayList<SecurityError>();
		
		KeyStore ks;
		try (FileInputStream fis = new java.io.FileInputStream(ksFile)){
			ks = KeyStore.getInstance(ksType);
			char[] password = null;
			
			if(ksPass.contains("::")) {
				String[] ksPassSecurityAlias = ksPass.split("::");
				String credentials[] = JavaStartParameters.getResourceUserAndPassword(ksPassSecurityAlias[0] +"::", "", ksPassSecurityAlias[1]);
				password = credentials[1].toCharArray();
			} else {
				password = ksPass.toCharArray();
			}
			
			ks.load(fis, password);
	        Enumeration<String> enumeration = ks.aliases();
	        while(enumeration.hasMoreElements()) {
	            String alias = enumeration.nextElement();

	            Certificate[] chain = ks.getCertificateChain(alias);
	            if (chain!=null){
		            for(Certificate cert : chain) {
		            	X509Certificate x509cert = (X509Certificate) cert;
		            	//x509cert.checkValidity(testDate);
		            	if(testDate.after(x509cert.getNotAfter())) {
		            		list.add(new SecurityError(String.format("Certificate will expire within %s days",CERTIFICATE_EXPIRATION_INTERVAL),
		            								String.format("keystore: %s, alias=%s",ksFile, alias)
		            								));
		            	}
		            }
	            } else {
	            	X509Certificate x509cert = (X509Certificate) ks.getCertificate(alias);
	            	
	            	if(testDate.after(x509cert.getNotAfter())) {
	            		list.add(new SecurityError(String.format("Certificate will expire within %s days",CERTIFICATE_EXPIRATION_INTERVAL),
								String.format("keystore: %s, alias=%s",ksFile, alias)
								));
	            	}
	            }
	        }
			
		} catch (KeyStoreException e) {
			LOGGER.severe(e.getMessage());
			//e.printStackTrace();
			list.add(new SecurityError("Error while reading keystore",ksFile));
		} catch (FileNotFoundException e1) {
			//e1.printStackTrace();
			LOGGER.severe(e1.getMessage());
			list.add(new SecurityError("File not found",ksFile));
		} catch (NoSuchAlgorithmException e) {
			//e.printStackTrace();
			LOGGER.severe(e.getMessage());
			list.add(new SecurityError("Invalid keystore type",ksFile));
		} catch (CertificateException e) {
			//e.printStackTrace();
			LOGGER.severe(e.getMessage());
			list.add(new SecurityError("Error while reading a certificate from keystore",ksFile));
		} catch (IOException e) {
			//e.printStackTrace();
			LOGGER.severe(e.getMessage());
			list.add(new SecurityError("Error while reading keystore",ksFile));
		} 

		
		return list;
		
	}

	public void copyMessageHeaders(MbMessage inMessage, MbMessage outMessage)
			throws MbException {
		MbElement outRoot = outMessage.getRootElement();

		// iterate though the headers starting with the first child of the root
		// element
		MbElement header = inMessage.getRootElement().getFirstChild();
		while (header != null && header.getNextSibling() != null) // stop before
																	// the last
																	// child
																	// (body)
		{
			// copy the header and add it to the out message
			outRoot.addAsLastChild(header.copy());
			// move along to next header
			header = header.getNextSibling();
		}
	}

}
