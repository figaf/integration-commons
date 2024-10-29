package com.figaf.integration.common.utils;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.JSONObject;

import static java.lang.String.format;

/**
 * @author Arsenii Istlentev
 */
public class Utils {

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
