package com.growmming.gurdening.repository;

import com.growmming.gurdening.domain.Category;
import com.growmming.gurdening.domain.Post;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    Slice<Post> findByCategory(Pageable pageable, Category category);
    Slice<Post> findAllBy(Pageable pageable);
    Slice<Post> findByTitleContaining(String keyword, Pageable pageable);
}
