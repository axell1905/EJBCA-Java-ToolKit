package com.toolbox.CreateUser;

import org.apache.log4j.BasicConfigurator;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateException;

public class CreateNewUser {
    //Crea un usuario (si es que no existe).
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, EjbcaException_Exception, AuthorizationDeniedException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, ApprovalException_Exception, CADoesntExistsException_Exception {

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
        UserDataVOWS user = new UserDataVOWS();
        user.setEmail("axell1905@gmail.com");
        user.setSubjectDN("CN=WSTESTUSER2,OU=10101010101,L=Lima,ST=Lima,C=PE");
        user.setCaName("EJBCA BMCert Intermediate CA");
        user.setSubjectAltName("RFC822Name=axell1905@gmail.com");
        user.setEndEntityProfileName("Persona Natural");
        user.setCertificateProfileName("Firma Digital");
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setSendNotification(true);

        //Crea el usuario (si no existe) y lo coloca en estado New
        ejbcaraws.editUser(user);


    }
}
