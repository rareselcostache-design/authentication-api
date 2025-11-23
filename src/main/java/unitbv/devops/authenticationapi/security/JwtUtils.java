package unitbv.devops.authenticationapi.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${jwt.secret:${JWT_SECRET:}}")
    private String jwtSecret;

    // 15 minutes access, 7 days refresh
    private final long accessTokenValidityMs = 15 * 60 * 1000L;
    private final long refreshTokenValidityMs = 7 * 24 * 60 * 60 * 1000L;

    private Key getSigningKey() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException("JWT secret not configured. Set 'jwt.secret' property or JWT_SECRET env var.");
        }

        byte[] keyBytes;
        // try base64 decode first
        try {
            keyBytes = Base64.getDecoder().decode(jwtSecret);
        } catch (IllegalArgumentException ignored) {
            // not base64, use raw bytes
            keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        }

        // Ensure key length >= 32 bytes for HS256. If shorter, derive via SHA-256
        if (keyBytes.length < 32) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                keyBytes = md.digest(keyBytes);
            } catch (NoSuchAlgorithmException e) {
                // fallback: pad to 32 bytes
                byte[] padded = new byte[32];
                System.arraycopy(keyBytes, 0, padded, 0, Math.min(keyBytes.length, padded.length));
                keyBytes = padded;
            }
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(String username, Collection<String> roles) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + accessTokenValidityMs);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshTokenValidityMs);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public Collection<String> getRolesFromAccessToken(String token) {
        Claims claims = parseClaims(token).getBody();
        Object roles = claims.get("roles");
        if (roles instanceof Collection) {
            return ((Collection<?>) roles).stream().map(Object::toString).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    public String getUsernameFromToken(String token) {
        return parseClaims(token).getBody().getSubject();
    }
}
