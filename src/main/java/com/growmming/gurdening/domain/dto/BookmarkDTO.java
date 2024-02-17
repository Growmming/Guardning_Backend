package com.growmming.gurdening.domain.dto;

import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.Post;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

public class BookmarkDTO {

    @Data
    @Builder
    @Getter
    public static class Response {
        private Long id;
        private Member member;
        private Post post;
    }
}
