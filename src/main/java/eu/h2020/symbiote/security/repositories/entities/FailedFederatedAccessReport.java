package eu.h2020.symbiote.security.repositories.entities;

import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = FailedFederatedAccessReport.REPORTS_COLLECTION_NAME)
public class FailedFederatedAccessReport {

    public static final String REPORTS_COLLECTION_NAME = "denied-federated-access-reports";

    private long timestamp;
    @Indexed
    private String targetPlatformId;
    @Indexed
    private String originPlatfomId;
    @Indexed
    private String federationId;
    private String resourceId;

    public FailedFederatedAccessReport(Long timestamp, String targetPlatformId, String originPlatfomId, String federationId, String resourceId) {
        this.targetPlatformId = targetPlatformId;
        this.originPlatfomId = originPlatfomId;
        this.federationId = federationId;
        this.resourceId = resourceId;
        this.timestamp = timestamp;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getTargetPlatformId() {
        return targetPlatformId;
    }

    public String getOriginPlatfomId() {
        return originPlatfomId;
    }

    public String getFederationId() {
        return federationId;
    }

    public String getResourceId() {
        return resourceId;
    }
}
