package com.growmming.gurdening.repository;

import com.growmming.gurdening.domain.Bookmark;
import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.Post;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BookmarkRepository extends JpaRepository<Bookmark, Long> {
    Optional<Bookmark> findByPostAndMember(Post post, Member member);
    Optional<Bookmark> findByMemberIdAndPostId(Long memberId, Long postId);
    List<Bookmark> findAllByMember(Member member);
}