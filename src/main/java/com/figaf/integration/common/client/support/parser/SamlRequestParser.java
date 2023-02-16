package com.figaf.integration.common.client.support.parser;

import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.exception.ParseSamlRequestException;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import static java.lang.String.format;

public class SamlRequestParser {

    private final static Pattern FETCH_SAML_ID_PATTERN = Pattern.compile("ID=\"([^\"]*)\".*");

    public static String fetchSamlRequestHeader(URI redirectUrl) {
        if (redirectUrl == null) {
            return null;
        }

        List<NameValuePair> parse = URLEncodedUtils.parse(redirectUrl, StandardCharsets.UTF_8);
        for (NameValuePair nameValuePair : parse) {
            if (nameValuePair.getName().equals("SAMLRequest")) {
                return nameValuePair.getValue();
            }
        }

        return null;
    }

    public static String fetchSamlRequestId(String samlRequest) {
        try {
            byte[] decodedSamlRequest = Base64.getDecoder().decode(samlRequest);
            String decompressedSamlRequest = decompressSamlRequest(decodedSamlRequest);

            return fetchId(decompressedSamlRequest);
        } catch (Exception ex) {
            throw new ParseSamlRequestException("Can't parse SAMLRequest", ex);
        }
    }

    private static String decompressSamlRequest(byte[] samlToken) throws DataFormatException {
        byte[] inflatedData = new byte[(10 * samlToken.length)];
        Inflater decompresser = new Inflater(true);
        decompresser.setInput(samlToken, 0, samlToken.length);
        int inflatedBytesLength = decompresser.inflate(inflatedData);
        decompresser.end();
        return new String(inflatedData, 0, inflatedBytesLength);
    }

    private static String fetchId(String decompressedSamlRequest) {
        Matcher matcher = FETCH_SAML_ID_PATTERN.matcher(decompressedSamlRequest);
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw new ClientIntegrationException(format("Can't find ID in the SAML request: %s", decompressedSamlRequest));
        }
    }
}
