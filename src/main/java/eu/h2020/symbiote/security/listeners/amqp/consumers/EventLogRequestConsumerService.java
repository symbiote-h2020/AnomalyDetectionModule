package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class EventLogRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(EventLogRequestConsumerService.class);
    private final EventManagerService eventManagerService;

    public EventLogRequestConsumerService(Channel channel, EventManagerService eventManagerService) {

        super(channel);
        this.eventManagerService = eventManagerService;
    }

    /**
     * Called when a <code><b>basic.deliver</b></code> is received for this consumer.
     *
     * @param consumerTag the <i>consumer tag</i> associated with the consumer
     * @param envelope    packaging data for the message
     * @param properties  content header data for the message
     * @param body        the message body (opaque, client-specific byte array)
     * @throws IOException if the consumer encounters an I/O error while processing the message
     * @see Envelope
     */
    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        ObjectMapper om = new ObjectMapper();
        EventLogRequest eventLogRequest;
            try {
                eventLogRequest = om.readValue(message, eu.h2020.symbiote.security.communication.payloads.EventLogRequest.class);
                log.info("I received log from AAM: " + om.writeValueAsString(eventLogRequest));
                if (eventLogRequest.getUsername() == null
                        || eventLogRequest.getUsername().isEmpty())
                    throw new IllegalArgumentException("Username/identifier should be provided");
                switch (eventLogRequest.getEventType()) {
                    case LOGIN_FAILED:
                        eventManagerService.addLoginFailEvent(eventLogRequest);
                        break;
                    case ACQUISITION_FAILED:
                        eventManagerService.addHomeTokenAcquisitionFailEvent(eventLogRequest);
                        break;
                    case VALIDATION_FAILED:
                        eventManagerService.addValidationFailEvent(eventLogRequest);
                        break;
                    default:
                        String msg = "Event type of AnomalyDetectionRequest was unrecognized";
                        log.error(msg);
                        throw new SecurityException(msg);
                }
            } catch (Exception e) {
                log.error(e);
            }
    }


}
