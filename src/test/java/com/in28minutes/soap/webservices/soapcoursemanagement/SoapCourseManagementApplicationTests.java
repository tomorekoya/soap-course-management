package com.in28minutes.soap.webservices.soapcoursemanagement;

import com.in28minutes.soap.webservices.soapcoursemanagement.security.ClientPasswordCallbackHandler;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import java.security.cert.X509Certificate;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SoapCourseManagementApplicationTests {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SoapCourseManagementApplicationTests.class);

    private static final javax.xml.namespace.QName SOAP_BODY = new javax.xml.namespace.QName(WSConstants.URI_SOAP11_ENV, "Body");

    private WSSecurityEngine secEngine = new WSSecurityEngine();

    private CallbackHandler passwordCallbackHandler = new ClientPasswordCallbackHandler();

    private byte[] keyData;

    private SecretKey key;

    private Crypto crypto;

    public SoapCourseManagementApplicationTests() throws Exception {
        crypto = CryptoFactory.getInstance(getEncryptionProperties());
    }

    private Properties getEncryptionProperties() {
        Properties properties = new Properties();
        properties.put("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "server-pass");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.alias", "server");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "config/serverkeystore.jks");

        return properties;
    }

    /**
     * Setup method
     *
     * @throws Exception Thrown when there is a problem in setup
     */
    @BeforeEach
    public void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();
        keyData = key.getEncoded();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA_15 algorithm to transport (wrap) the symmetric
     * key.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testEncryptionDecryptionRSA15() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("server");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        LOG.info("Before Encryption Triple DES....");

        LOG.info("Unencrypted Document:");
        LOG.info(XMLUtils.prettyDocumentToString(doc));

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);
        LOG.info("After Encryption Triple DES....");

        String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);

        LOG.info("Encrypted message, RSA-15 keytransport, 3DES:");
        LOG.info(outputString);

        assertFalse(outputString.contains("counter_port_type"));
        verify(encryptedDoc, passwordCallbackHandler, SOAP_BODY);
    }


    @Test
    public void testEncryptionDecryptionPublicKey() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("server");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertNotNull(certs);
        builder.setUseThisPublicKey(certs[0].getPublicKey());

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);

        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        assertFalse(outputString.contains("counter_port_type"));

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results = newEngine.processSecurityHeader(encryptedDoc, null, passwordCallbackHandler, crypto);

        WSSecurityEngineResult actionResult = results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_PUBLIC_KEY));
    }

    @Test
    void contextLoads() {
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @param handler
     * @param expectedEncryptedElement
     * @throws Exception Thrown when there is a problem in verification
     */
    @SuppressWarnings("unchecked")
    private WSHandlerResult verify(Document doc, CallbackHandler handler, javax.xml.namespace.QName expectedEncryptedElement) throws Exception {
        final WSHandlerResult results = secEngine.processSecurityHeader(doc, null, handler, null, crypto);
        String outputString = XMLUtils.prettyDocumentToString(doc);

        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        assertTrue(outputString.indexOf("counter_port_type") > 0);
        //
        // walk through the results, and make sure there is an encryption
        // action, together with a reference to the decrypted element
        // (as a QName)
        //
        boolean encrypted = false;

        for (WSSecurityEngineResult result : results.getResults()) {
            final Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            assertNotNull(action);

            if ((action & WSConstants.ENCR) != 0) {
                final java.util.List<WSDataRef> refs = (java.util.List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                assertNotNull(refs);
                encrypted = true;

                for (WSDataRef ref : refs) {
                    assertNotNull(ref.getName());
                    assertEquals(expectedEncryptedElement, ref.getName());
                    assertNotNull(ref.getProtectedElement());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("WSDataRef element: ");
                        LOG.debug(DOM2Writer.nodeToString(ref.getProtectedElement()));
                    }
                }
            }
        }

        assertTrue(encrypted);
        return results;
    }

}
