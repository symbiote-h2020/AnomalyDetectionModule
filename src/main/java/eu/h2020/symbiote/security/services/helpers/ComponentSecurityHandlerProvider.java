package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ComponentSecurityHandlerProvider {


    private IComponentSecurityHandler componentSecurityHandler;

    public ComponentSecurityHandlerProvider(@Value("${adm.security.KEY_STORE_FILE_NAME}") String keyStoreFileName,
                                            @Value("${adm.security.KEY_STORE_PASSWORD}") String keyStorePassword,
                                            @Value("${adm.deployment.owner.username}") String AAMOwnerUsername,
                                            @Value("${adm.deployment.owner.password}") String AAMOwnerPassword,
                                            @Value("${symbIoTe.core.interface.url}") String coreAAMAddress) throws
            SecurityHandlerException {

        componentSecurityHandler = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                keyStoreFileName,
                keyStorePassword,
                "adm@" + SecurityConstants.CORE_AAM_INSTANCE_ID,
                coreAAMAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
    }

    public IComponentSecurityHandler getComponentSecurityHandler() {
        return componentSecurityHandler;
    }

    public HomeCredentials getHomeCredentials() throws SecurityHandlerException {
        return componentSecurityHandler.getLocalAAMCredentials().homeCredentials;
    }
}
