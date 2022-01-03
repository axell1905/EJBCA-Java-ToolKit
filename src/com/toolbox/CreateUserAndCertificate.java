package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;
import org.ejbca.core.protocol.ws.common.CertificateHelper;

import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CreateUserAndCertificate {
    //Crea un usuario (si es que no existe) y un certificado con su respectiva llave privada.
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, EjbcaException_Exception, AuthorizationDeniedException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, ApprovalException_Exception {

        //Iniciar Conexión con EJBCA
        //================================================================================
        BasicConfigurator.configure();
        CryptoProviderTools.installBCProvider();
        String urlstr = "https://ejbca.local:8443/ejbca/ejbcaws/ejbcaws?wsdl";

        //El truststore debe tener la cadena de certificados del SSL del servidor web, el SSL debe ser un nombre válido
        System.setProperty("javax.net.ssl.trustStore","p12/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword","123456");

        //El keystore del certificado de usuario con el que iniciamos sesión
        System.setProperty("javax.net.ssl.keyStore","p12/superadmin 12-2021.p12");
        System.setProperty("javax.net.ssl.keyStorePassword","12345678");

        QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr),qname);
        EjbcaWS ejbcaraws = service.getEjbcaWSPort();
        //================================================================================

        //Ingresa datos de la cuenta a crear
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER1");
        user1.setSubjectDN("CN=WSTESTUSER1");
        user1.setCaName("EJBCA BMCert Intermediate CA");
        user1.setSubjectAltName("DNSName=WSTESTUSER1");
        user1.setEndEntityProfileName("SSL-Administration");
        user1.setCertificateProfileName("SSL-ADMINISTRATION");

        //Genera el par de llaves
        KeyPair keys = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

        //Genera el CSR
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=Unused"), keys.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keys.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        //Envía el CSR a la CA y obtiene la respuesta en forma de certificado
        CertificateResponse certenv =  ejbcaraws.certificateRequest(user1, new String (Base64.encode(csr.getEncoded())), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        X509Certificate cert = certenv.getCertificate();

        System.out.println();
        System.out.println("Certificado emitido satisfactoriamente");
        System.out.println("DN: "+ cert.getSubjectX500Principal().getName());
        System.out.println("Número de serie: "+cert.getSerialNumber().toString(16));
        System.out.println("Válido desde: "+cert.getNotBefore().toString());
        System.out.println("Válido hasta: "+cert.getNotAfter().toString());
        System.out.println();

        //Imprime el certificado en formato PEM
        StringWriter writer = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        pemWriter.close();
        System.out.println("Certificate:\n"+writer);

        //Imprime la llave privada en formato PEM
        StringWriter writer2 = new StringWriter();
        JcaPEMWriter pemWriter2 = new JcaPEMWriter(writer2);
        pemWriter2.writeObject(keys.getPrivate());
        pemWriter2.flush();
        pemWriter2.close();
        System.out.println("Private Key:\n"+writer2);

    }
}
