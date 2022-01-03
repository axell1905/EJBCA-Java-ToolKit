package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;

public class RevokeCertificates {
    //Revoca un certificado con el DN del emisor, el Serial y una razón de revocación.
    public static void main(String[] args) throws MalformedURLException {

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

        try
        {
            ejbcaraws.revokeCert("CN = BManagement2021CA,O = BMTech Peru S.A.C.,L = Lima,ST = Lima,C = PE", "2D4055461A8BA8F112DAF5495A52B0C7B1AD3BDD", RevokeStatus.REVOKATION_REASON_AACOMPROMISE);
            System.out.println("Certificado revocado correctamente.");
        }
        catch (AlreadyRevokedException_Exception | ApprovalException_Exception | AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception | NotFoundException_Exception | WaitingForApprovalException_Exception ex)
        {
            if (ex.toString().contains("Certificate is already revoked"))
            {
                System.out.println("El certificado ya se encuentra revocado.");
            }
            else if (ex.toString().contains("Could not find end entity certificate"))
            {
                System.out.println("El certificado indicado no existe.");
            }
            else if (ex.toString().contains("CA with id") && ex.toString().contains("does not exist"))
            {
                System.out.println("La CA indicada no existe.");
            }
            else
                System.out.println(ex);
        }
    }
}
