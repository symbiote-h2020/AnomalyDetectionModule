package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.EventType;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

/**
 * Entity, in which identifiers of the users are kept, for whom error occured during login.
 * Contains timestamp of the last error, identifier of the user (username in this case) and a counter of errors occured in short time.
 *
 * @author Jakub Toczek
 */
public class EventLog {
    @Id
    private final String identifier;
    private long firstError = 0;
    private long lastError = 0;
    @Indexed
    private EventType eventType = EventType.NULL;
    private int counter = 0;

    /**
     * Constructor for entity in repositories.
     * @param identifier identifier of the user/component/token
     * @param firstError timestamp of the first error in the specified time
     * @param lastError timestamp of the last error in the specified time
     * @param eventType type of the error
     */

    public EventLog(String identifier, long firstError, long lastError, EventType eventType) {
        this.identifier = identifier;
        this.firstError = firstError;
        this.lastError = lastError;
        this.eventType = eventType;
        counter = 1;
    }

    public EventType getEventType() {
        return eventType;
    }

    public long getFirstError() {
        return firstError;
    }

    public long getLastError() {
        return lastError;
    }

    /**
     * adds a new error - timestamp is updated and in case of errors in short time, counter is incremented
     *
     * @param lastError - timestamp of a new error for particular identifier
     */
    public void setLastError(long lastError) {
        if (lastError > this.lastError + SecurityConstants.ANOMALY_DETECTION_DELTA) {
            counter = 0;
            this.firstError = lastError;
        }
        counter++;
        this.lastError = lastError;
    }

    public int getCounter() {
        return counter;
    }

    public String getIdentifier() {
        return identifier;
    }
}
