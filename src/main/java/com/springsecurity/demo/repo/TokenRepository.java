package com.springsecurity.demo.repo;

import com.springsecurity.demo.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {
    @Query("""
            SELECT t FROM Token t INNER JOIN User u on t.user.id = u.id
            WHERE u.id = :userId AND (t.expired = false OR t.revoked = false)
            """)
    List<Token> findAllValidTokensByUser(Integer userId);

    Optional<Token> findByToken(String token);
}
