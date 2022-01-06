package com.toolbox.CreateUser;

import org.apache.log4j.BasicConfigurator;
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertKeyPFX {
    //Crea un usuario (si es que no existe) y un certificado con su respectiva llave privada en formato PFX.
    public static void main(String[] args) throws IOException, OperatorCreationException, CertificateException, EjbcaException_Exception, AuthorizationDeniedException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, ApprovalException_Exception, InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException {

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
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=Test"), keys.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keys.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        //Envía el CSR a la CA y obtiene la respuesta en forma de certificado
        CertificateResponse certenv =  ejbcaraws.certificateRequest(user1, new String (Base64.encode(csr.getEncoded())), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        X509Certificate cert = certenv.getCertificate();

        //Convierte el certificado a un array
        Certificate[] certi = new Certificate[1];
        certi[0] = cert;

        //Crea una entrada con la llave privada y el certificado
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keys.getPrivate(), certi);

        //Crea un keystore en formato PKCS12 y lo inicializa
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        //Agrega la entrada al keystore con el alias y clave especificados
        ks.setEntry("alias", privateKeyEntry, new KeyStore.PasswordProtection("pass".toCharArray()));

        //Almacena el keystore en un archivo en la ubicación y con la clave indicada
        ks.store(new FileOutputStream("test.pfx"), "pass".toCharArray());

    }
}
