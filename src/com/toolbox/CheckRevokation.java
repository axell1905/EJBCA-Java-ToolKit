package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;

public class CheckRevokation {
    //Muestra la versión de la instancia EJBCA a la que conecta.
    public static void main(String[] args) throws MalformedURLException, CADoesntExistsException_Exception, EjbcaException_Exception, AuthorizationDeniedException_Exception {

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

        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus("CN = BManagement2021CA,O = BMTech Peru S.A.C.,L = Lima,ST = Lima,C = PE", "500C5B02F8680C16491886579E9B2771E95C00DB");
        if(revokestatus != null)
        {
            if ( revokestatus.getReason() != RevokeStatus.NOT_REVOKED)
            {
                System.out.println("El certificado está revocado.");
            }
            else
            {
                System.out.println("El certificado no está revocado.");
            }
        }
        else
        {
            System.out.println("El certificado no existe.");
        }

    }
}
