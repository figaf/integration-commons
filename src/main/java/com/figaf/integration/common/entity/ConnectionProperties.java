package com.figaf.integration.common.entity;

import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;

/**
 * @author Ilya Nesterov
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(of = {"username", "host", "port", "protocol"})
public class ConnectionProperties implements Serializable {

    private String username;
    private String password;
    private String host;
    private String port;
    private String protocol;

    public ConnectionProperties(String url, String username, String password) {
        Pattern pattern = Pattern.compile("(https?):\\/\\/([^:]+):*(\\d*)");
        Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            this.protocol = matcher.group(1);
            this.host = matcher.group(2);
            this.port = matcher.group(3);
        }
        this.username = username;
        this.password = password;
    }

    public static String buildUrl(String protocol, String host, String port) {
        return String.format("%s://%s%s", protocol, host, port != null ? ":" + port : "");
    }

    public String getURL() {
        StringBuilder urlBuilder = new StringBuilder();

        if (protocol.toUpperCase().equals("HTTPS")) {
            urlBuilder.append("https://");
        } else {
            urlBuilder.append("http://");
        }
        urlBuilder.append(host);
        urlBuilder.append(":");
        urlBuilder.append(port);
        return urlBuilder.toString();
    }

    public String getUrlRemovingDefaultPortIfNecessary() {
        if ("http".equals(protocol) && Objects.equals(port, "80") || "https".equals(protocol) && Objects.equals(port, "443")) {
            return buildUrl(protocol, host, null);
        } else {
            return buildUrl(protocol, host, port);
        }
    }
}
