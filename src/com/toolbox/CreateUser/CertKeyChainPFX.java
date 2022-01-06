package com.toolbox.CreateUser;

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
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Iterator;

public class CertKeyChainPFX {
    //Crea un usuario (si es que no existe) y un certificado con su respectiva llave privada y cadena en formato PFX.
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, EjbcaException_Exception, AuthorizationDeniedException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, ApprovalException_Exception, KeyStoreException, NoSuchAlgorithmException {

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

        //Envía el CSR a la CA y obtiene la respuesta en forma de PKCS#7 con el certificado y la cadena
        CertificateResponse certenv =  ejbcaraws.certificateRequest(user1, new String (Base64.encode(csr.getEncoded())), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN);
        byte[] raw = certenv.getRawData();

        //Obtiene un grupo de certificados a partir de la respuesta anterior
        InputStream in = new ByteArrayInputStream(raw);
        CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
        Iterator it = cf.generateCertificates(in).iterator();
        int i=0;

        //Crea un array para almacenar los certificados que irán en el PFX
        Certificate[] cadena = new Certificate[3];

        //Obtiene cada certificado por separado, lo imprime en pantalla y lo almacena en el array
        while ( it.hasNext() )
        {

            X509Certificate cert = (X509Certificate)it.next();
            cadena[i] = cert;
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(cert);
            pemWriter.flush();
            pemWriter.close();
            i++;
            System.out.println("Certificate" + i + ":\n"+writer);
        }

        //Imprime la llave privada en formato PEM
        StringWriter writer2 = new StringWriter();
        JcaPEMWriter pemWriter2 = new JcaPEMWriter(writer2);
        pemWriter2.writeObject(keys.getPrivate());
        pemWriter2.flush();
        pemWriter2.close();
        System.out.println("Private Key:\n"+writer2);

        //Crea una entrada con la llave privada, el certificado y la cadena
        PrivateKeyEntry privateKeyEntry = new PrivateKeyEntry(keys.getPrivate(), cadena);

        //Crea un keystore en formato PKCS12 y lo inicializa
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        //Agrega la entrada al keystore con el alias y clave especificados
        ks.setEntry("alias", privateKeyEntry, new KeyStore.PasswordProtection("pass".toCharArray()));

        //Almacena el keystore en un archivo en la ubicación y con la clave indicada
        ks.store(new FileOutputStream("testcadena.p12"), "pass".toCharArray());

    }
}
