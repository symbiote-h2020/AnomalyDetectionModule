package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.AbstractADMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;

@Profile("test")
@Configuration
public class TestComponentSecurityHandlerProvider {

    private final String KEY_STORE_FILE_NAME = "keystores/core_adm.p12";
    private final String CERTIFICATE_ALIAS = "adm";
    private final String ROOT_CERTIFICATE_ALIAS = "core-1";
    private final String KEY_STORE_PASSWORD = "1234567";

    @Bean
    @Primary
    public ComponentSecurityHandlerProvider componentSecurityHandlerProvider() throws SecurityHandlerException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException {
        ComponentSecurityHandlerProvider componentSecurityHandlerProvider = Mockito.mock(ComponentSecurityHandlerProvider.class);
        AAM aam = new AAM("",
                "",
                "",
                new Certificate(
                        CryptoHelper.convertX509ToPEM(AbstractADMTestSuite.getCertificateFromTestKeystore(
                                KEY_STORE_FILE_NAME,
                                KEY_STORE_PASSWORD,
                                ROOT_CERTIFICATE_ALIAS))),
                new HashMap<>()
        );
        HomeCredentials homeCredentials = new HomeCredentials(aam,
                "",
                "",
                new Certificate(
                        CryptoHelper.convertX509ToPEM(AbstractADMTestSuite.getCertificateFromTestKeystore(
                                KEY_STORE_FILE_NAME,
                                KEY_STORE_PASSWORD,
                                CERTIFICATE_ALIAS))),
                AbstractADMTestSuite.getPrivateKeyTestFromKeystore(KEY_STORE_FILE_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD, CERTIFICATE_ALIAS));

        Mockito.when(componentSecurityHandlerProvider.getHomeCredentials()).thenReturn(homeCredentials);
        return componentSecurityHandlerProvider;
    }
}
