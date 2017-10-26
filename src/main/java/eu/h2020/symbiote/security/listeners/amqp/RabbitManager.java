package eu.h2020.symbiote.security.listeners.amqp;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Consumer;
import eu.h2020.symbiote.security.listeners.amqp.consumers.EventLogRequestConsumerService;
import eu.h2020.symbiote.security.services.EventManagerService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * Manages AMQP listeners
 */
@Component
public class RabbitManager {
    private static Log log = LogFactory.getLog(RabbitManager.class);
    private Connection connection;
    private final EventManagerService eventManagerService;

    @Value("${rabbit.host}")
    private String rabbitHost;
    @Value("${rabbit.username}")
    private String rabbitUsername;
    @Value("${rabbit.password}")
    private String rabbitPassword;

    @Value("${rabbit.exchange.adm.name}")
    private String AAMExchangeName;
    @Value("${rabbit.exchange.adm.type}")
    private String AAMExchangeType;
    @Value("${rabbit.exchange.adm.durable}")
    private boolean AAMExchangeDurable;
    @Value("${rabbit.exchange.adm.autodelete}")
    private boolean AAMExchangeAutodelete;
    @Value("${rabbit.exchange.adm.internal}")
    private boolean AAMExchangeInternal;

    @Value("${rabbit.queue.event}")
    private String eventLogQueue;
    @Value("${rabbit.routingKey.event}")
    private String eventLogRoutingKey;

    @Autowired
    public RabbitManager(EventManagerService eventManagerService) {
        this.eventManagerService = eventManagerService;
    }

    /**
     * Initiates connection with Rabbit server using parameters from Bootstrap Properties
     *
     * @throws IOException IOException
     * @throws TimeoutException TimeoutException
     */
    private Connection getConnection() throws IOException, TimeoutException {
        if (connection == null) {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost(this.rabbitHost);
            factory.setUsername(this.rabbitUsername);
            factory.setPassword(this.rabbitPassword);
            this.connection = factory.newConnection();
        }
        return this.connection;
    }

    /**
     * Closes given channel if it exists and is open.
     *
     * @param channel rabbit channel to close
     */
    private void closeChannel(Channel channel) {
        try {
            if (channel != null && channel.isOpen())
                channel.close();
        } catch (IOException | TimeoutException e) {
            log.error(e);
        }
    }

    /**
     * Method creates channel and declares Rabbit exchanges for AAM features.
     * It triggers start of all consumers used in with AAM communication.
     */
    public void init() throws IOException, TimeoutException {
        Channel channel;
        getConnection();

        if (connection != null) {
            channel = this.connection.createChannel();

            channel.exchangeDeclare(this.AAMExchangeName,
                    this.AAMExchangeType,
                    this.AAMExchangeDurable,
                    this.AAMExchangeAutodelete,
                    this.AAMExchangeInternal,
                    null);
            startConsumers();
        }
    }

    private void startConsumers() throws IOException {
        startConsumerOfLoginFail();
    }

    private void startConsumerOfLoginFail() throws IOException {
        String queueName = this.eventLogQueue;

        Channel channel;

        channel = this.connection.createChannel();
        channel.queueDeclare(queueName, true, false, false, null);
        channel.queueBind(queueName, this.AAMExchangeName, this.eventLogRoutingKey);

        log.info("Anomaly Detection Module waiting for login fail logs");

        Consumer consumer = new EventLogRequestConsumerService(channel, eventManagerService);
        channel.basicConsume(queueName, false, consumer);
    }

    @PreDestroy
    public void cleanup() {

        log.info("Rabbit cleaned!");
        try {
            Channel channel;
            if (this.connection != null && this.connection.isOpen()) {
                channel = connection.createChannel();

                //login fail logs
                channel.queueUnbind(this.eventLogQueue, this.AAMExchangeName,
                        this.eventLogRoutingKey);
                channel.queueDelete(this.eventLogQueue);

                closeChannel(channel);
                this.connection.close();
            }
        } catch (IOException e) {
            log.error(e);
        }
    }
}
