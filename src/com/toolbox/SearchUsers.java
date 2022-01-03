package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class SearchUsers {
    //Busca usuarios según texto contenido en el DN u otro atributo seleccionado.
    public static void main(String[] args) throws MalformedURLException, EjbcaException_Exception, AuthorizationDeniedException_Exception, EndEntityProfileNotFoundException_Exception, IllegalQueryException_Exception {

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

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_DN); // Definir con qué atributo comparar
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS); // Inicia, contiene o equivale
        usermatch.setMatchvalue("local"); // Valor a comparar
        List<UserDataVOWS> result = ejbcaraws.findUser(usermatch);

        if (result.size() == 0)
        {
            System.out.println("No se hallaron coincidencias");
        }
        else
        for (int i=0;i<result.size();i++)
        {
            UserDataVOWS data = result.get(i);
            System.out.println();
            System.out.println("Cuenta #"+(i+1));
            System.out.println("Usuario: "+data.getUsername());
            System.out.println("DN: "+data.getSubjectDN());
            System.out.println("Estado: "+ EndEntityConstants.getStatusText(data.getStatus()));
            System.out.println("Emisor: "+data.getCaName());
            System.out.println("Perfil de certificado: "+data.getCertificateProfileName());
            System.out.println("Perfil de usuario final: "+data.getEndEntityProfileName());

        }
    }
}
