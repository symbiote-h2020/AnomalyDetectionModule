package eu.h2020.symbiote.security.repositories.entities;

import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = FailedFederatedAccessReport.REPORTS_COLLECTION_NAME)
public class FailedFederatedAccessReport {

    public static final String REPORTS_COLLECTION_NAME = "denied-federated-access-reports";

    private final long timestamp;
    @Indexed
    private final String targetPlatformId;
    @Indexed
    private final String originPlatformId;
    @Indexed
    private final String federationId;
    private final String resourceId;

    public FailedFederatedAccessReport(Long timestamp,
                                       String targetPlatformId,
                                       String originPlatformId,
                                       String federationId,
                                       String resourceId) {
        this.targetPlatformId = targetPlatformId;
        this.originPlatformId = originPlatformId;
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

    public String getOriginPlatformId() {
        return originPlatformId;
    }

    public String getFederationId() {
        return federationId;
    }

    public String getResourceId() {
        return resourceId;
    }
}
