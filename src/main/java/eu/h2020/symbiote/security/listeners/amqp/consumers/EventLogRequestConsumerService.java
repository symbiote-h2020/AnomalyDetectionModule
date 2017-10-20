package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

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
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                eventLogRequest = om.readValue(message, eu.h2020.symbiote.security.communication.payloads.EventLogRequest.class);
                log.info("I received log from AAM");
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
                response = om.writeValueAsString("OK");
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (Exception e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
            log.info("Event was saved");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }


}
