package com.growmming.gurdening.domain;

import com.growmming.gurdening.util.StringListConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Transient;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Post extends BaseTimeEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "post_id")
    private Long id;

    @Column(nullable = false)
    private String title;

    @Enumerated(EnumType.STRING)
    private Category category;

    @Column(nullable = false)
    private int viewCount;

    @Column(nullable = false, columnDefinition = "TEXT")
    @Convert(converter = StringListConverter.class)
    private List<String> content;

    @Column(nullable = false, columnDefinition = "TEXT")
    @Convert(converter = StringListConverter.class)
    private List<String> images;

    @Column(nullable = false)
    private int likeCount;

    @Transient // JPA에서 해당 필드가 데베의 테이블의 열에 해당하지 않음. DB에 저장, 조회되지 않음.
    private boolean isBookmarked;

    public void updateViewCount() {
        this.viewCount++;
    }

    public void updateIsBookmarked(boolean isBookmarked) {
        this.isBookmarked = isBookmarked;
    }

}