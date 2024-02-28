package com.figaf.integration.common.client;

import com.figaf.integration.common.factory.CloudConnectorAccessTokenProvider;
import com.figaf.integration.common.factory.CloudConnectorParameters;
import com.figaf.integration.common.socket.ConnectivitySocks5ProxySocket;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sun.mail.smtp.SMTPTransport;
import lombok.extern.slf4j.Slf4j;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Properties;

@Slf4j
public class CloudConnectorEmailClient {

    private final static String MAIL_MIME_CHARSET_KEY = "mail.mime.charset";
    private final static String MAIL_PROTOCOL_KEY = "mail.transport.protocol";
    private final static String MAIL_PROTOCOL = "smtp";
    private final static String UTF_8 = "UTF-8";
    private final CloudConnectorParameters cloudConnectorParameters;
    private final String destinationHost;
    private final String locationId;
    private final int destinationPort;

    public CloudConnectorEmailClient(
        CloudConnectorParameters cloudConnectorParameters,
        String destinationHost,
        String locationId,
        int destinationPort
    ) {
        this.cloudConnectorParameters = cloudConnectorParameters;
        this.destinationHost = destinationHost;
        this.locationId = locationId;
        this.destinationPort = destinationPort;
    }

    public void sendEmail(
        String content,
        String typeOfContent,
        String subject,
        String sentTo
    ) throws IOException, MessagingException {
        log.debug(
            "#sendEmail: content={}, typeOfContent={}, recipients={}, sccLocationId={}",
            content,
            typeOfContent,
            sentTo,
            this.locationId
        );

        CloudConnectorAccessTokenProvider cloudConnectorAccessTokenProvider = new CloudConnectorAccessTokenProvider();
        OAuth2TokenResponse oAuth2TokenResponse = cloudConnectorAccessTokenProvider.getToken(cloudConnectorParameters);

        try (Socket socket = new ConnectivitySocks5ProxySocket(
            oAuth2TokenResponse.getAccessToken(),
            locationId,
            cloudConnectorParameters.getConnectionProxyHost(),
            cloudConnectorParameters.getConnectionProxyPortSocks5())
        ) {
            socket.connect(new InetSocketAddress(destinationHost, destinationPort));
            Session session = Session.getInstance(createProperties());
            SMTPTransport transport = (SMTPTransport) session.getTransport(MAIL_PROTOCOL);
            MimeMessage msg = new MimeMessage(session);
            msg.setContent(content, typeOfContent);
            msg.setSubject(subject);
            msg.addRecipients(Message.RecipientType.TO, sentTo);
            transport.connect(socket);
            transport.sendMessage(msg, msg.getAllRecipients());
        }
    }

    private Properties createProperties() {
        Properties props = new Properties();
        props.put(MAIL_PROTOCOL_KEY, MAIL_PROTOCOL);
        props.put(MAIL_MIME_CHARSET_KEY, UTF_8);
        return props;
    }
}
