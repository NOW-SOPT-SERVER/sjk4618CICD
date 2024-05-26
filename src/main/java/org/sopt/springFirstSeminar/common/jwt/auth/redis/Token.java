package org.sopt.springFirstSeminar.common.jwt.auth.redis;


import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;
//import org.springframework.data.redis.core.RedisHash;
//import org.springframework.data.redis.core.index.Indexed;

//@RedisHash(value = "", timeToLive = 60 * 60 * 24 * 1000L * 1)
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
@Entity
public class Token {

    @Id
    private Long id;

//    @Indexed
    private String refreshToken;

    public static Token of(final Long id, final String refreshToken) {
        return Token.builder()
                .id(id)
                .refreshToken(refreshToken)
                .build();
    }
}
