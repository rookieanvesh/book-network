package com.second.book.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository extends JpaRepository<Token, Integer> {
//optional for null values and to avoid null pointer exception
    Optional<Token> findByToken(String token);


}
