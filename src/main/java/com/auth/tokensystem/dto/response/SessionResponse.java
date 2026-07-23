package com.auth.tokensystem.dto.response;

import com.auth.tokensystem.model.RefreshToken;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class SessionResponse {

    private String id;
    private String deviceInfo;
    private String ipAddress;
    private Instant lastUsed;
    private Instant issuedAt;
    private boolean isCurrent;

    public static SessionResponse from(RefreshToken token, String currentTokenValue) {
        SessionResponse dto = new SessionResponse();
        dto.setId(token.getId());
        dto.setDeviceInfo(token.getDeviceInfo());
        dto.setIpAddress(token.getIpAddress());
        dto.setLastUsed(token.getLastUsed());
        dto.setIssuedAt(token.getIssuedAt());
        dto.setCurrent(token.getToken().equals(currentTokenValue));
        return dto;
    }
}
