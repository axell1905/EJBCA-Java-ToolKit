package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class GetAvailableCA {
    //Muestra la lista de CAs disponibles de la instancia EJBCA a la que conecta.
    public static void main(String[] args) throws MalformedURLException, EjbcaException_Exception, AuthorizationDeniedException_Exception {

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

        List<NameAndId> availableCA = ejbcaraws.getAvailableCAs();
        for (int i=0;i<availableCA.size();i++)
        {
            NameAndId data = availableCA.get(i);
            System.out.println();
            System.out.println("CA #" + (i+1));
            System.out.println("ID de CA: " + data.getId());
            System.out.println("Nombre de CA: " + data.getName());
        }


    }
}
