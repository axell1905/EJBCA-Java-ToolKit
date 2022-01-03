package com.toolbox;

import org.apache.log4j.BasicConfigurator;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.*;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

public class RevokeCertsPerUser {
    //Muestra los certificados de un usuario, y permite seleccionar uno para ser revocado.
    public static void main(String[] args) throws MalformedURLException, EjbcaException_Exception, AuthorizationDeniedException_Exception, CertificateException, CADoesntExistsException_Exception {

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

        List<Certificate> foundcertificates = ejbcaraws.findCerts("testrazones2", false);
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
            System.out.println("Num. Serie: "+ x509Cert.getSerialNumber());
            System.out.println("Inicio: "+ x509Cert.getNotBefore());
            System.out.println("Fin: "+ x509Cert.getNotAfter());
            RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(x509Cert.getIssuerX500Principal().toString(), x509Cert.getSerialNumber().toString(16));
            if ( revokestatus.getReason() != RevokeStatus.NOT_REVOKED)
            {
                System.out.println("Revocado: Sí");
            }
            else
            {
                System.out.println("Revocado: No");
            }
            System.out.println();
        }
        Scanner text = new Scanner(System.in);
        System.out.println("Ingrese número de certificado a revocar");
        int indextorevoke = text.nextInt() - 1;
        if (indextorevoke + 1 > foundcertificates.size())
        {
            System.out.println("Número de certificado inválido");
        }
        else
        {
            Certificate certtorevoke = foundcertificates.get(indextorevoke);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(certtorevoke.getRawCertificateData());
            X509Certificate x509Certtorevoke = (X509Certificate)cf.generateCertificate(in);
            System.out.println("Desea revocar el certificado con Serie "+x509Certtorevoke.getSerialNumber() + "?") ;
            System.out.println("Ingrese sí para aceptar");
            String sirevoca = text.next();
            if (sirevoca.equalsIgnoreCase("s") || sirevoca.equalsIgnoreCase("si") || sirevoca.equalsIgnoreCase("sí"))
            {
                try
                {
                    ejbcaraws.revokeCert(x509Certtorevoke.getIssuerX500Principal().toString(), x509Certtorevoke.getSerialNumber().toString(16), RevokeStatus.REVOKATION_REASON_SUPERSEDED);
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
                    {
                        System.out.println(ex);
                    }

                }
            }
        }


    }
}
