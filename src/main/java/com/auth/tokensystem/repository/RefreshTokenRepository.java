package com.auth.tokensystem.repository;

import com.auth.tokensystem.model.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUserAndDeviceInfo(String user, String deviceInfo);

    List<RefreshToken> findByUserOrderByLastUsedDesc(String user);

    long countByUser(String user);

    Optional<RefreshToken> findFirstByUserOrderByLastUsedAsc(String user);

    void deleteByToken(String token);

    void deleteByUserAndTokenNot(String user, String token);

    void deleteByUser(String user);
}
