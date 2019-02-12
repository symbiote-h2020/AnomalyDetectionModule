package eu.h2020.symbiote.security.utils;

import com.github.fakemongo.Fongo;
import com.mongodb.Mongo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

/**
 * Configuration which allows running tests on embedded MongoDB
 *
 * @author Dariusz Krajewski (Intern at PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("fongo")
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
public class EmbeddedMongoDatabase extends AbstractMongoConfiguration {
    @Value("${adm.database.name}")
    String databaseName;

    @Override
    public String getDatabaseName() {
        return databaseName;
    }

    @Bean
    @Override
    public Mongo mongo() {
        return new Fongo(databaseName).getMongo();
    }
}
