package dev.folomkin.springsecurityjwtmaster.utils;

import dev.folomkin.springsecurityjwtmaster.entities.Role;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.xml.crypto.Data;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtTokenUtils { //-> "JwtTokenProvider"

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.lifetime}")
    private Duration jwtLifetime;

    public String generatedToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        List<String> rolesList = userDetails
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority).toList();

        claims.put("roles", rolesList);

        Instant issuedDate = Instant.now();
        Instant expiredDate = issuedDate.plus(jwtLifetime);
        Date expiryDate = Date.from(expiredDate);

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(issuedDate))
                .expiration(expiryDate)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .compact();
    }

    public String getUserName(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    public List<String> getRoles(String token) {
        return getAllClaimsFromToken(token).get("roles", List.class);
    }

    // => Новая версия
    public Claims getAllClaimsFromToken(String token) {
        // Создаем SecretKey из секрета (для HS256)
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        // Строим парсер
        JwtParser parser = Jwts.parser()
                .verifyWith(key)  // Верификация подписи (для JWS)
                .build();

        try {
            // Парсим как signed JWT (JWS)
            Jws<Claims> jws = parser.parseSignedClaims(token);
            return jws.getPayload();  // Возвращаем claims (body)
        } catch (JwtException e) {
            // Обработка ошибок: неверный токен, истекший, подделка и т.д.
            throw new IllegalArgumentException("Invalid JWT token: " + e.getMessage());
        }
    }
}
