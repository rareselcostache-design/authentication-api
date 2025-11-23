package unitbv.devops.authenticationapi.token;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import unitbv.devops.authenticationapi.user.entity.User;

import java.util.Optional;

@Service
public class TokenService {

    private final TokenRepository tokenRepository;

    public TokenService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Transactional
    public Token storeTokens(User user, String access, String refresh) {
        Token t = new Token();
        t.setUser(user);
        t.setAccessToken(access);
        t.setRefreshToken(refresh);
        t.setBlacklisted(false);
        return tokenRepository.save(t);
    }

    @Transactional
    public void blacklist(String access, String refresh) {
        if (access != null) {
            tokenRepository.findByAccessToken(access).ifPresent(t -> {
                t.setBlacklisted(true);
                tokenRepository.save(t);
            });
        }
        if (refresh != null) {
            tokenRepository.findByRefreshToken(refresh).ifPresent(t -> {
                t.setBlacklisted(true);
                tokenRepository.save(t);
            });
        }
    }

    public boolean isAccessTokenBlacklisted(String access) {
        if (access == null) return false;
        Optional<Token> ot = tokenRepository.findByAccessToken(access);
        return ot.map(Token::isBlacklisted).orElse(false);
    }

    public Optional<Token> findByRefreshToken(String refresh) {
        if (refresh == null) return Optional.empty();
        return tokenRepository.findByRefreshToken(refresh);
    }
}
