package com.growmming.gurdening.domain.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

public class MemberDTO {

    @Data
    @Getter
    @Builder
    public static class RequestLogin {
        private String accessToken;
    }

}
