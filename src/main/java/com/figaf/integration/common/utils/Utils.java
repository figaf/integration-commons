package com.figaf.integration.common.utils;

import org.json.JSONObject;

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

}
