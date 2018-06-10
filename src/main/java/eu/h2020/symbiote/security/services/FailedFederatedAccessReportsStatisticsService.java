package eu.h2020.symbiote.security.services;

import com.mongodb.Block;
import com.mongodb.MongoClient;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.repositories.entities.FailedFederatedAccessReport;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

import static com.mongodb.client.model.Filters.eq;

/**
 * Service responsible for provisioning reports statistics of failed federation authorization
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class FailedFederatedAccessReportsStatisticsService {

    private static final String TARGET_PLATFORM_ID_FIELD_NAME = "targetPlatformId";
    private static final String ORIGIN_PLATFORM_ID_FIELD_NAME = "originPlatformId";
    private static final String FEDERATION_ID_FIELD_NAME = "federationId";
    private final MongoDatabase mongoDatabase;
    private int total = 0;

    @Autowired
    public FailedFederatedAccessReportsStatisticsService(
            @Value("${adm.database.name}") String databaseName,
            MongoClient mongoClient) {
        this.mongoDatabase = mongoClient.getDatabase(databaseName);
    }

    public Map<String, OriginPlatformGroupedPlatformMisdeedsReport> getMisdeedsGroupedByPlatform(
            String platformIdFilter,
            String singleSearchOriginPlatformFilter) {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = new HashMap<>();
        MongoCollection mongoCollection = mongoDatabase.getCollection(FailedFederatedAccessReport.REPORTS_COLLECTION_NAME);
        List<String> platformList = new ArrayList<>();
        if (platformIdFilter == null) {
            mongoCollection.distinct(TARGET_PLATFORM_ID_FIELD_NAME, String.class).into(platformList);
        } else {
            platformList.add(platformIdFilter);
        }

        for (String targetPlatform : platformList) {
            List<String> searchOriginPlatformsList = new ArrayList<>();
            if (singleSearchOriginPlatformFilter == null) {
                mongoCollection.distinct(ORIGIN_PLATFORM_ID_FIELD_NAME, eq(TARGET_PLATFORM_ID_FIELD_NAME, targetPlatform), String.class).into(searchOriginPlatformsList);
            } else {
                searchOriginPlatformsList.add(singleSearchOriginPlatformFilter);
            }

            Map<String, Map<String, Integer>> originPlatformGroupedPlatformMisdeedsReportMap = new HashMap<>();
            total = 0;
            for (String originPlatform : searchOriginPlatformsList) {
                Map<String, Integer> federationIdCountMap = new HashMap<>();
                AggregateIterable<Document> iterable = mongoCollection.aggregate(
                        Arrays.asList(
                                new Document("$match",
                                        new Document(TARGET_PLATFORM_ID_FIELD_NAME, targetPlatform)
                                                .append(ORIGIN_PLATFORM_ID_FIELD_NAME, originPlatform)),
                                new Document("$group",
                                        new Document("_id", "$" + FEDERATION_ID_FIELD_NAME).append("count", new Document("$sum", 1))))
                );
                iterable.forEach((Block<Document>) document -> {
                    total += (int) document.get("count");
                    federationIdCountMap.put(document.get("_id").toString(), (Integer) document.get("count"));
                });
                originPlatformGroupedPlatformMisdeedsReportMap.put(originPlatform, federationIdCountMap);
            }
            response.put(targetPlatform, new OriginPlatformGroupedPlatformMisdeedsReport(total, originPlatformGroupedPlatformMisdeedsReportMap));
        }
        return response;
    }

    public Map<String, FederationGroupedPlatformMisdeedsReport> getMisdeedsGroupedByFederations(
            String platformIdFilter,
            String federationIdFilter) {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = new HashMap<>();
        MongoCollection mongoCollection = mongoDatabase.getCollection(FailedFederatedAccessReport.REPORTS_COLLECTION_NAME);
        List<String> platformList = new ArrayList<>();
        if (platformIdFilter == null) {
            mongoCollection.distinct(TARGET_PLATFORM_ID_FIELD_NAME, String.class).into(platformList);
        } else {
            platformList.add(platformIdFilter);
        }

        for (String targetPlatform : platformList) {
            List<String> federationList = new ArrayList<>();
            if (federationIdFilter == null) {
                mongoCollection.distinct(FEDERATION_ID_FIELD_NAME, eq(TARGET_PLATFORM_ID_FIELD_NAME, targetPlatform), String.class).into(federationList);
            } else {
                federationList.add(federationIdFilter);
            }

            Map<String, Map<String, Integer>> federationGroupedPlatformMisdeedsReportMap = new HashMap<>();
            total = 0;
            for (String federationId : federationList) {
                Map<String, Integer> originPlatforIdCountMap = new HashMap<>();
                AggregateIterable<Document> iterable = mongoCollection.aggregate(
                        Arrays.asList(
                                new Document("$match",
                                        new Document(TARGET_PLATFORM_ID_FIELD_NAME, targetPlatform)
                                                .append(FEDERATION_ID_FIELD_NAME, federationId)),
                                new Document("$group",
                                        new Document("_id", "$" + ORIGIN_PLATFORM_ID_FIELD_NAME).append("count", new Document("$sum", 1))))
                );
                iterable.forEach((Block<Document>) document -> {
                    total += (int) document.get("count");
                    originPlatforIdCountMap.put(document.get("_id").toString(), (Integer) document.get("count"));
                });
                federationGroupedPlatformMisdeedsReportMap.put(federationId, originPlatforIdCountMap);
            }
            response.put(targetPlatform, new FederationGroupedPlatformMisdeedsReport(total, federationGroupedPlatformMisdeedsReportMap));
        }
        return response;
    }
}
