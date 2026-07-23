package com.auth.tokensystem.repository;

import com.auth.tokensystem.model.BlacklistedToken;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {

    boolean existsByToken(String token);
}
