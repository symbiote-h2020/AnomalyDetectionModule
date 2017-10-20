package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.data.annotation.Id;

/**
 * Entity, in which identifiers of the users are kept, for whom error occured during login.
 * Contains timestamp of the last error, identifier of the user (username in this case) and a counter of errors occured in short time.
 *
 * @author Jakub Toczek
 */
public class EventLog {
    @Id
    private final String identifier;
    private long lastError = 0;
    private int counter = 0;

    /**
     * Constructor for entity in LoginErrorRepository.
     *
     * @param identifier actors username
     * @param lastError  timestamp of the login fail
     */
    public EventLog(String identifier, long lastError) {
        this.identifier = identifier;
        this.lastError = lastError;
        counter = 1;
    }

    public int getCounter() {
        return counter;
    }

    /**
     * adds a new error - timestamp is updated and in case of errors in short time, counter is incremented
     *
     * @param lastError - timestamp of a new error for particular identifier
     */
    public void setLastError(long lastError) {
        if (lastError > this.lastError + SecurityConstants.ANOMALY_DETECTION_DELTA) {
            counter = 0;
        }
        counter++;
        this.lastError = lastError;
    }

    public String getIdentifier() {
        return identifier;
    }
}
