package com.auth.tokensystem.repository;

import com.auth.tokensystem.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.time.Instant;
import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByVerificationToken(String verificationToken);

    Optional<User> findByPasswordResetTokenAndPasswordResetTokenTimeAfter(
            String passwordResetToken, Instant now);
}
