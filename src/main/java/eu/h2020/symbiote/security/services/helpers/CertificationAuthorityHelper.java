package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class CertificationAuthorityHelper {
    private final X509Certificate admCertificate;
    private final X509Certificate rootCertificationAuthorityCertificate;
    private final PrivateKey admPrivateKey;

    public CertificationAuthorityHelper(ComponentSecurityHandlerProvider componentSecurityHandlerProvider) throws
            SecurityHandlerException,
            CertificateException,
            SecurityMisconfigurationException {

        ECDSAHelper.enableECDSAProvider();
        admCertificate = componentSecurityHandlerProvider.getHomeCredentials().certificate.getX509();
        admPrivateKey = componentSecurityHandlerProvider.getHomeCredentials().privateKey;
        rootCertificationAuthorityCertificate = componentSecurityHandlerProvider.getHomeCredentials().homeAAM.getAamCACertificate().getX509();
        if (!getADMPlatformInstanceIdentifier().equals(SecurityConstants.CORE_AAM_INSTANCE_ID)) {
            throw new SecurityMisconfigurationException("Platform id does not match this in provided certificate. Check btm.platformId property or check the keystore.");
        }
    }

    /**
     * @return resolves the adm instance identifier using the AAM certificate
     */
    public String getADMInstanceIdentifier() {
        return getADMCertificate().getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
    }

    public String getADMPlatformInstanceIdentifier() {
        return getADMInstanceIdentifier().split(CryptoHelper.FIELDS_DELIMITER)[1];
    }

    /**
     * @return Retrieves ADM's certificate in PEM format
     */
    public String getADMCert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getADMCertificate());
    }

    /**
     * @return Retrieves RootCA's certificate in PEM format
     */
    public String getRootCACert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getRootCACertificate());
    }

    /**
     * @return RootCA certificate in X509 format
     */
    public X509Certificate getRootCACertificate() {
        return rootCertificationAuthorityCertificate;
    }

    /**
     * @return ADM certificate in X509 format
     */
    public X509Certificate getADMCertificate() {
        return admCertificate;
    }

    /**
     * @return Retrieves ADM's public key from provisioned JavaKeyStore
     */
    public PublicKey getADMPublicKey() {
        return admCertificate.getPublicKey();
    }

    /**
     * @return retrieves ADM's private key from provisioned JavaKeyStore
     */
    public PrivateKey getADMPrivateKey() {
        return admPrivateKey;
    }
}
