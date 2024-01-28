package com.growmming.gurdening.domain.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

public class UserDTO {

    @Data
    @Getter
    @Builder
    public static class RequestLogin {
        private String googleToken;
    }
}
