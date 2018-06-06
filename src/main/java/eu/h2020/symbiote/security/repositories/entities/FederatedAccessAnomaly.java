package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

import java.util.HashMap;
import java.util.Map;

public class FederatedAccessAnomaly {

    @Id
    private String id;
    @Indexed
    private String federationId;
    private String platformId;
    private String resourceId;
    private Map<String, Integer> reporters = new HashMap<>();

    /**
     * for mongo usage
     */
    public FederatedAccessAnomaly() {

    }

    public FederatedAccessAnomaly(String federationId, String platformId, String resourceId, String reporter) {
        this.id = createId(federationId, platformId, resourceId);
        this.federationId = federationId;
        this.platformId = platformId;
        this.resourceId = resourceId;
        reporters.put(reporter, 1);
    }

    public static String createId(String federationId, String platformId, String resourceId) {
        return federationId + CryptoHelper.FIELDS_DELIMITER + platformId + CryptoHelper.FIELDS_DELIMITER + resourceId;
    }

    public Map<String, Integer> getReporters() {
        return reporters;
    }

    public String getId() {
        return id;
    }

    public String getFederationId() {
        return federationId;
    }

    public String getPlatformId() {
        return platformId;
    }

    public String getResourceId() {
        return resourceId;
    }


}
