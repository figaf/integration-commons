package com.figaf.integration.common.entity.message_sender;

import com.figaf.integration.common.entity.AuthenticationType;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import static com.figaf.integration.common.entity.AuthenticationType.*;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.springframework.util.Assert.isTrue;

/**
 * @author Klochkov Sergey
 */
@Getter
@RequiredArgsConstructor
@ToString
public class MessageSendingAdditionalProperties {

    private final AuthenticationType authenticationType;
    private final String oauthUrl;
    private final String restTemplateWrapperKey;
    private final boolean csrfProtected;
    // creates a simple custom RequestCallback from provided headers and body, used for raw multipart requests
    private final boolean rawMode;

    public static MessageSendingAdditionalProperties basicAuthorization(
        String restTemplateWrapperKey,
        boolean csrfProtected
    ) {
        return basicAuthorization(restTemplateWrapperKey, csrfProtected, false);
    }

    public static MessageSendingAdditionalProperties basicAuthorization(
        String restTemplateWrapperKey,
        boolean csrfProtected,
        boolean skipAllRequestConverters
    ) {
        isTrue(isNotBlank(restTemplateWrapperKey), "Rest template wrapper key must be not empty!");
        return new MessageSendingAdditionalProperties(
            BASIC,
            null,
            restTemplateWrapperKey,
            csrfProtected,
            skipAllRequestConverters
        );
    }

    public static MessageSendingAdditionalProperties oauth(
        String oauthUrl,
        String restTemplateWrapperKey,
        boolean csrfProtected
    ) {
        return oauth(oauthUrl, restTemplateWrapperKey, csrfProtected, false);
    }

    public static MessageSendingAdditionalProperties oauth(
        String oauthUrl,
        String restTemplateWrapperKey,
        boolean csrfProtected,
        boolean skipAllRequestConverters
    ) {
        isTrue(isNotBlank(oauthUrl), "Oauth url must be not empty!");
        isTrue(isNotBlank(restTemplateWrapperKey), "Rest template wrapper key must be not empty!");
        return new MessageSendingAdditionalProperties(
            OAUTH,
            oauthUrl,
            restTemplateWrapperKey,
            csrfProtected,
            skipAllRequestConverters
        );
    }

}
