package eu.h2020.symbiote.security.config;

import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;


/**
 * Used by components with MongoDB
 *
 * @author mateuszl
 * @author Mikołaj Dobski
 */
@Profile("!test")
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
class AppConfig extends AbstractMongoConfiguration {

    private final Object syncObject = new Object();
    private String databaseName;
    private String databaseHost;
    private MongoClient mongoClient = null;

    AppConfig(@Value("${adm.database.name}") String databaseName,
              @Value("${adm.database.host:localhost}") String databaseHost) {
        this.databaseName = databaseName;
        this.databaseHost = databaseHost;
    }

    @Override
    protected String getDatabaseName() {
        return databaseName;
    }

    @Bean
    @Override
    public Mongo mongo() {
        synchronized (syncObject) {
            if (mongoClient == null) {
                mongoClient = new MongoClient(databaseHost);
            }
        }
        return mongoClient;
    }


}