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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SignExternalCSRtoPEM {
    //Crea un usuario (si es que no existe) y un certificado con su respectiva llave privada en formato PEM, usando un CSR externo.
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, EjbcaException_Exception, AuthorizationDeniedException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, ApprovalException_Exception {

        //Iniciar Conexión con EJBCA
        //================================================================================
        BasicConfigurator.configure();
        CryptoProviderTools.installBCProvider();
        String urlstr = "https://ejbca.local:8443/ejbca/ejbcaws/ejbcaws?wsdl";

        //El truststore debe tener la cadena de certificados del SSL del servidor web, el SSL debe ser un nombre válido
        System.setProperty("javax.net.ssl.trustStore", "p12/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "123456");

        //El keystore del certificado de usuario con el que iniciamos sesión
        System.setProperty("javax.net.ssl.keyStore", "p12/superadmin 12-2021.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "12345678");

        QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
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

        //Lee el CSR desde un archivo
        Path path = Path.of("CSR.txt");
        String CSR = Files.readString(path);

        //Envía el CSR a la CA y obtiene la respuesta en forma de certificado
        CertificateResponse certenv =  ejbcaraws.certificateRequest(user1, CSR, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
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

        //Exporta el certificado a un archivo en formato PEM
        FileOutputStream os = new FileOutputStream("cert.crt");
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.write(Base64.encode(cert.getEncoded(), true));
        os.write("\n-----END CERTIFICATE-----".getBytes("US-ASCII"));
        os.close();
    }
}
