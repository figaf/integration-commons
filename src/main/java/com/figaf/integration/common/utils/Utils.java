package com.figaf.integration.common.utils;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.JSONObject;

import java.sql.Timestamp;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.Date;

import static java.lang.String.format;

/**
 * @author Arsenii Istlentev
 */
public class Utils {

    private static final DateTimeFormatter DATE_FORMATTER = new DateTimeFormatterBuilder()
        .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
        .optionalStart()
        .appendPattern(".SSS")
        .optionalEnd()
        .optionalStart()
        .appendLiteral('Z')
        .optionalEnd()
        .toFormatter()
        .withZone(ZoneId.of("GMT"));

    public static Date parseDate(String date) {
        try {
            if (date == null) {
                return null;
            }
            if (date.matches(".*Date\\(.*\\).*")) {
                return new Timestamp(
                    Long.parseLong(
                        date.replaceAll("[^0-9]", "")
                    )
                );
            } else {
                ZonedDateTime zdt = ZonedDateTime.parse(date, DATE_FORMATTER);
                return Date.from(zdt.toInstant());
            }
        } catch (Exception ex) {
            throw new RuntimeException("Can't parse date: ", ex);
        }
    }

    public static String optString(JSONObject json, String key) {
        if (json.isNull(key)) {
            return null;
        } else {
            return json.optString(key, null);
        }
    }

    /**
     * @return message and root cause message with formats:
     * - if message and root cause message are identical: "{error message}"
     * - if message and root cause message are different: "{error message}. Root cause: {root cause message}"
     */
    public static String extractMessageAndRootCauseMessage(Throwable ex, boolean withExceptionClass) {
        String errorMessage = ExceptionUtils.getMessage(ex);
        String rootCauseMessage = ExceptionUtils.getRootCauseMessage(ex);
        if (StringUtils.equals(errorMessage, rootCauseMessage)) {
            return withExceptionClass ? errorMessage : ex.getMessage();
        } else {
            return format("%s. Root cause: %s", withExceptionClass ? errorMessage : ex.getMessage(), rootCauseMessage);
        }
    }

}
