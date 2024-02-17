package com.growmming.gurdening.controller;

import com.growmming.gurdening.domain.Bookmark;
import com.growmming.gurdening.service.BookmarkService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/bookmarks")
public class BookmarkController {

    @Autowired
    private BookmarkService bookmarkService;

    @PostMapping("/{memberId}/{postId}")
    public ResponseEntity<Bookmark> addBookmark(@PathVariable Long memberId, @PathVariable Long postId) {
        Bookmark bookmark = bookmarkService.addBookmark(memberId, postId);
        return ResponseEntity.ok(bookmark);
    }

    @DeleteMapping("/{memberId}/{postId}")
    public ResponseEntity<Void> deleteBookmark(@PathVariable Long memberId, @PathVariable Long postId) {
        bookmarkService.deleteBookmark(memberId, postId);
        return ResponseEntity.noContent().build();
    }
}