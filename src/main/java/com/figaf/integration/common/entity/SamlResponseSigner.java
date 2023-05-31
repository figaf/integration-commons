package com.figaf.integration.common.entity;

public interface SamlResponseSigner {

    String sign(String agentId, String samlRequestId);
}
