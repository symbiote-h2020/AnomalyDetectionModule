package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.data.annotation.Id;

public class AbusePlatformEntry {

    @Id
    private String platformId;
    private long lastAbuseTimestamp;
    private int counter = 0;

    public AbusePlatformEntry(String platformId, long lastAbuseTimestamp) {
        this.platformId = platformId;
        this.lastAbuseTimestamp = lastAbuseTimestamp;
        this.counter = 1;
    }

    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
    }

    public long getLastAbuseTimestamp() {
        return lastAbuseTimestamp;
    }


    public void setLastAbuseTimestamp(long lastAbuseTimestamp) {
        if(this.lastAbuseTimestamp<lastAbuseTimestamp)
            this.lastAbuseTimestamp = lastAbuseTimestamp;
        this.counter++;

        this.lastAbuseTimestamp = lastAbuseTimestamp;
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }
}
