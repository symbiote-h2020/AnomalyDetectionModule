package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

@Component
public class EventLogRequestConsumerService {

    private static Log log = LogFactory.getLog(EventLogRequestConsumerService.class);
    private final EventManagerService eventManagerService;

    public EventLogRequestConsumerService(EventManagerService eventManagerService) {
        this.eventManagerService = eventManagerService;
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.event}",
                    durable = "${rabbit.exchange.adm.durable}",
                    autoDelete = "${rabbit.exchange.adm.autodelete}",
                    exclusive = "false"),
            exchange = @Exchange(
                    value = "${rabbit.exchange.adm.name}",
                    ignoreDeclarationExceptions = "true",
                    durable = "${rabbit.exchange.adm.durable}",
                    autoDelete = "${rabbit.exchange.adm.autodelete}",
                    internal = "${rabbit.exchange.adm.internal}",
                    type = "${rabbit.exchange.adm.type}"),
            key = "${rabbit.routingKey.event}"))
    public void eventLog(byte[] body) {

        String message = null;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
        }
        ObjectMapper om = new ObjectMapper();

        try {
            EventLogRequest eventLogRequest = om.readValue(message, EventLogRequest.class);
            log.info("I received log from AAM: " + om.writeValueAsString(eventLogRequest));
            if (eventLogRequest.getUsername() == null
                    || eventLogRequest.getUsername().isEmpty())
                throw new IllegalArgumentException("Username/identifier should be provided");
            eventManagerService.handleEvent(eventLogRequest);
        } catch (IllegalArgumentException | InvalidArgumentsException | WrongCredentialsException | IOException e) {
            log.error(e);
        }
    }


}
