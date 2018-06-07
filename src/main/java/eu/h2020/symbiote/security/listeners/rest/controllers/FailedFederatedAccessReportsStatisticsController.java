package eu.h2020.symbiote.security.listeners.rest.controllers;

import com.mongodb.Block;
import com.mongodb.MongoClient;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import eu.h2020.symbiote.security.communication.payloads.FederationGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.communication.payloads.OriginPlatformGroupedPlatformMisdeedsReport;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IFailedFederatedAccessReportsStatistics;
import eu.h2020.symbiote.security.repositories.entities.FailedFederatedAccessReport;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

import static com.mongodb.client.model.Filters.eq;

@RestController
public class FailedFederatedAccessReportsStatisticsController implements IFailedFederatedAccessReportsStatistics {

    private final MongoDatabase mongoDatabase;
    private int total = 0;

    @Autowired
    public FailedFederatedAccessReportsStatisticsController(@Value("${adm.database.name}") String databaseName,
                                                            MongoClient mongoClient) {
        this.mongoDatabase = mongoClient.getDatabase(databaseName);
    }

    @Override
    public ResponseEntity<Map<String, OriginPlatformGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByPlatform(String platformIdFilter, String singleSearchOriginPlatformFilter) {
        Map<String, OriginPlatformGroupedPlatformMisdeedsReport> response = new HashMap<>();
        MongoCollection mongoCollection = mongoDatabase.getCollection(FailedFederatedAccessReport.REPORTS_COLLECTION_NAME);
        List<String> platformList = new ArrayList<>();
        if (platformIdFilter == null) {
            mongoCollection.distinct("targetPlatformId", String.class).into(platformList);
        } else {
            platformList.add(platformIdFilter);
        }

        for (String targetPlatform : platformList) {
            List<String> searchOriginPlatformsList = new ArrayList<>();
            if (singleSearchOriginPlatformFilter == null) {
                mongoCollection.distinct("originPlatfomId", eq("targetPlatformId", targetPlatform), String.class).into(searchOriginPlatformsList);
            } else {
                searchOriginPlatformsList.add(singleSearchOriginPlatformFilter);
            }

            Map<String, Map<String, Integer>> map2 = new HashMap<>();
            total = 0;
            for (String originPlatform : searchOriginPlatformsList) {
                Map<String, Integer> map = new HashMap<>();
                AggregateIterable<Document> iterable = mongoCollection.aggregate(
                        Arrays.asList(
                                new Document("$match",
                                        new Document("targetPlatformId", targetPlatform)
                                                .append("originPlatfomId", originPlatform)),
                                new Document("$group",
                                        new Document("_id", "$" + "federationId").append("count", new Document("$sum", 1))))
                );
                iterable.forEach((Block<Document>) document -> {
                    total += (int) document.get("count");
                    map.put(document.get("_id").toString(), (Integer) document.get("count"));
                });
                map2.put(originPlatform, map);
            }
            response.put(targetPlatform, new OriginPlatformGroupedPlatformMisdeedsReport(total, map2));
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<Map<String, FederationGroupedPlatformMisdeedsReport>> getMisdeedsGroupedByFederations(String platformIdFilter, String federationIdFilter) {
        Map<String, FederationGroupedPlatformMisdeedsReport> response = new HashMap<>();
        //TODO
        if (platformIdFilter == null) {

        } else {

        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
