package com.growmming.gurdening.service;

import com.growmming.gurdening.domain.Bookmark;
import com.growmming.gurdening.domain.Member;
import com.growmming.gurdening.domain.Post;
import com.growmming.gurdening.repository.BookmarkRepository;
import com.growmming.gurdening.repository.MemberRepository;
import com.growmming.gurdening.repository.PostRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class BookmarkService {

    @Autowired
    private BookmarkRepository bookmarkRepository;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PostRepository postRepository;

    @Transactional
    public Bookmark addBookmark(Long memberId, Long postId) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new IllegalArgumentException("회원이 존재하지 않습니다. id=" + memberId));
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new IllegalArgumentException("게시글이 존재하지 않습니다. id=" + postId));

        Bookmark bookmark = Bookmark.builder()
                .member(member)
                .post(post)
                .build();
        return bookmarkRepository.save(bookmark);
    }

    @Transactional
    public void deleteBookmark(Long memberId, Long postId) {
        Bookmark bookmark = bookmarkRepository.findByMemberIdAndPostId(memberId, postId)
                .orElseThrow(() -> new IllegalArgumentException("북마크가 존재하지 않습니다."));
        bookmarkRepository.delete(bookmark);
    }
}