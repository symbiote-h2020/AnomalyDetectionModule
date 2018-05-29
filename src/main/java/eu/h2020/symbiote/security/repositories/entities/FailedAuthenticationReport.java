package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

public class FailedAuthenticationReport {

    @Id
    private String id;
    @Indexed
    private String federationId;
    private String platformId;
    private String resourceId;
    private long counter = 1;

    public FailedAuthenticationReport(String id, String federationId, String platformId, String resourceId, long counter) {
        this.id = id;
        this.federationId = federationId;
        this.platformId = platformId;
        this.resourceId = resourceId;
        this.counter = counter;
    }

    public FailedAuthenticationReport(String federationId, String platformId, String resourceId) {
        this.id = createId(federationId, platformId, resourceId);
        this.federationId = federationId;
        this.platformId = platformId;
        this.resourceId = resourceId;
    }

    public static String createId(String federationId, String platformId, String resourceId) {
        return federationId + CryptoHelper.FIELDS_DELIMITER + platformId + CryptoHelper.FIELDS_DELIMITER + resourceId;
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

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public void increaseCounter() {
        this.counter++;
    }
}
