package unitbv.devops.authenticationapi.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import unitbv.devops.authenticationapi.security.JwtUtils;
import unitbv.devops.authenticationapi.token.TokenService;
import unitbv.devops.authenticationapi.user.entity.User;
import unitbv.devops.authenticationapi.user.repository.UserRepository;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthTokenController {

    private final JwtUtils jwtUtils;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    public AuthTokenController(JwtUtils jwtUtils, TokenService tokenService, UserRepository userRepository) {
        this.jwtUtils = jwtUtils;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    public static class TokenRefreshRequest {
        public String accessToken;
        public String refreshToken;
    }

    @PostMapping("/token")
    public ResponseEntity<?> refreshTokens(@RequestBody TokenRefreshRequest req) {
        if (req == null || req.refreshToken == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "refreshToken required"));
        }

        if (!jwtUtils.validateToken(req.refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid refresh token"));
        }

        Optional<unitbv.devops.authenticationapi.token.Token> stored = tokenService.findByRefreshToken(req.refreshToken);
        if (stored.isEmpty() || stored.get().isBlacklisted()) {
            return ResponseEntity.status(401).body(Map.of("error", "refresh token not valid"));
        }

        String username = jwtUtils.getUsernameFromToken(req.refreshToken);
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("error", "user not found"));
        }

        User user = userOpt.get();

        // blacklist provided pair
        tokenService.blacklist(req.accessToken, req.refreshToken);

        Collection<String> roles;
        if (req.accessToken != null && jwtUtils.validateToken(req.accessToken)) {
            roles = jwtUtils.getRolesFromAccessToken(req.accessToken);
        } else {
            roles = user.getRoles().stream().map(Enum::name).toList();
        }

        String newAccess = jwtUtils.generateAccessToken(user.getUsername(), roles);
        String newRefresh = jwtUtils.generateRefreshToken(user.getUsername());
        tokenService.storeTokens(user, newAccess, newRefresh);

        return ResponseEntity.ok(Map.of(
                "accessToken", newAccess,
                "refreshToken", newRefresh
        ));
    }
}

