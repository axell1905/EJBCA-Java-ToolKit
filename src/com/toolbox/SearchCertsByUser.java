package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.xml.namespace.QName;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

public class SearchCertsByUser {
    //Busca los certificados emitidos para un usuario y muestra el número de serie, inicio, fin, si está revocado y, de ser así, la razón.
    public static void main(String[] args) throws MalformedURLException, EjbcaException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, CertificateException {

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

        //El boolean indica si queremos obviar los certificados revocados y expirados
        List<Certificate> foundcertificates = ejbcaraws.findCerts("testrazones", false);
        System.out.println("Certificados encontrados: "+foundcertificates.size());
        Iterator it = foundcertificates.iterator();
        int i=0;
        while (it.hasNext())
        {
            Certificate cert = (Certificate) it.next();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(cert.getRawCertificateData());
            X509Certificate x509Cert = (X509Certificate)cf.generateCertificate(in);
            i++;
            System.out.println();
            System.out.println("Certificado "+i);
            System.out.println("Num. Serie: "+ x509Cert.getSerialNumber().toString(16).toUpperCase());
            System.out.println("Inicio: "+ x509Cert.getNotBefore());
            System.out.println("Fin: "+ x509Cert.getNotAfter());
            RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(x509Cert.getIssuerX500Principal().toString(), x509Cert.getSerialNumber().toString(16));
            if ( revokestatus.getReason() != RevokeStatus.NOT_REVOKED)
            {
                System.out.println("Revocado: Sí");
                System.out.println("Razón: "+ razonRevocacion(revokestatus.getReason()));
            }
            else
            {
                System.out.println("Revocado: No");
            }

            System.out.println();

        }
    }

    public static String razonRevocacion (int razon)
    {
        String textorazon = "";
        if (razon == RevokeStatus.REVOKATION_REASON_SUPERSEDED)
        {
            textorazon = "Reemplazado";
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE)
        {
            textorazon = "Llave comprometida";
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_CESSATIONOFOPERATION)
        {
            textorazon = "Cese de operación";
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_PRIVILEGESWITHDRAWN)
        {
            textorazon = "Privilegios retirados"; //EJBCA lo marca como unused - código 7
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_REMOVEFROMCRL)
        {
            textorazon = "Removido de la CRL"; //No aparece desde EJBCA
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_AFFILIATIONCHANGED)
        {
            textorazon = "Afiliación cambiada";
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_AACOMPROMISE)
        {
            textorazon = "AA comprometida"; //No se puede seleccionar desde EJBCA
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD)
        {
            textorazon = "Certificado retenido"; //Reversible
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_CACOMPROMISE)
        {
            textorazon = "CA comprometida";
        }
        else if (razon == RevokeStatus.REVOKATION_REASON_UNSPECIFIED)
        {
            textorazon = "No especificada";
        }
        else textorazon = "No identificada. Código "+razon;

        return textorazon;
    }
}
