package com.growmming.gurdening.domain.dto;

import com.google.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

public class TokenDTO {

    @Data
    @Builder
    @AllArgsConstructor
    public static class GoogleToken {
        private String accessToken;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class ServiceToken {
        private String accessToken;
        private String refreshToken;
    }
}
