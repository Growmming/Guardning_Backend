package com.growmming.gurdening.domain.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

public class ImageDTO {

    @Data
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private String imageName;
        private String imageUrl;
    }
}
