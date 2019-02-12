package eu.h2020.symbiote.security.config;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Configuration
public class SpringConfigValidator {

    private final String serviceIdentifier;
    private final ApplicationContext ctx;

    public SpringConfigValidator(@Value("${platform.id}") String serviceIdentifier,
                                 ApplicationContext ctx) throws SecurityMisconfigurationException {
        this.serviceIdentifier = serviceIdentifier;
        this.ctx = ctx;
        validateSpringProfileDeploymentTypeMatch();
    }


    private void validateSpringProfileDeploymentTypeMatch() throws
            SecurityMisconfigurationException {
        List<String> activeProfiles = Arrays.asList(ctx.getEnvironment().getActiveProfiles());
        if (serviceIdentifier.equals(SecurityConstants.CORE_AAM_INSTANCE_ID)
                && !activeProfiles.contains("core"))
            throw new SecurityMisconfigurationException("You are loading Core ADM setup. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=core'");
    }
}
