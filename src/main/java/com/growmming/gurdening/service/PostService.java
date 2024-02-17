package com.growmming.gurdening.service;

import com.growmming.gurdening.domain.Category;
import com.growmming.gurdening.domain.Post;
import com.growmming.gurdening.domain.dto.PostDTO;
import com.growmming.gurdening.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class PostService {

    private final PostRepository postRepository;

    @Transactional(readOnly = true)
    public PostDTO.Response getPost(Long id) {
        Post post = postRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("해당하는 Post가 없습니다. id=" + id));

        return PostDTO.Response.builder()
                .id(post.getId())
                .title(post.getTitle())
                .category(post.getCategory())
                .viewCount(post.getViewCount())
                .content(post.getContent())
                .images(post.getImages())
                .likeCount(post.getLikeCount())
                .build();
    }

    @Transactional(readOnly = true)
    public Slice<PostDTO.Response> getPostsByCategory(Pageable pageable, Category category) {
        Slice<Post> posts = postRepository.findByCategory(pageable, category);

        return posts.map(post -> PostDTO.Response.builder()
                .id(post.getId())
                .title(post.getTitle())
                .category(post.getCategory())
                .viewCount(post.getViewCount())
                .content(post.getContent())
                .images(post.getImages())
                .likeCount(post.getLikeCount())
                .build());
    }

    @Transactional(readOnly = true)
    public Page<PostDTO.Response> getListOfPosts(Pageable pageable) {
        Page<Post> posts = postRepository.findAll(pageable);

        return posts.map(post -> PostDTO.Response.builder()
                .id(post.getId())
                .title(post.getTitle())
                .category(post.getCategory())
                .viewCount(post.getViewCount())
                .content(post.getContent())
                .images(post.getImages())
                .likeCount(post.getLikeCount())
                .build());
    }

}