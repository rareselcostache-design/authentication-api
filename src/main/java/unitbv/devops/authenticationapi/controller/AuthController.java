package unitbv.devops.authenticationapi.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import unitbv.devops.authenticationapi.dto.auth.LoginRequest;
import unitbv.devops.authenticationapi.dto.auth.LoginResponse;
import unitbv.devops.authenticationapi.dto.auth.RegisterRequest;
import unitbv.devops.authenticationapi.dto.auth.UserResponse;
import unitbv.devops.authenticationapi.user.service.UserService;
import unitbv.devops.authenticationapi.user.repository.UserRepository;
import unitbv.devops.authenticationapi.user.entity.User;
import unitbv.devops.authenticationapi.token.TokenService;
import unitbv.devops.authenticationapi.security.JwtUtils;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService service;
    private final JwtUtils jwtUtils;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    public AuthController(UserService service, JwtUtils jwtUtils, TokenService tokenService, UserRepository userRepository) {
        this.service = service;
        this.jwtUtils = jwtUtils;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest request) {
        return service.register(request)
                .<ResponseEntity<?>>map(user -> ResponseEntity.status(HttpStatus.CREATED).body(user))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(new SimpleError("Username or email already in use")));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        return service.login(request)
                .map(userResp -> {
                    // locate full User entity to extract roles and persist tokens
                    Optional<User> found = userRepository.findByUsername(userResp.username());
                    if (found.isEmpty()) {
                        // try by email
                        found = userRepository.findByEmail(userResp.email());
                    }

                    if (found.isEmpty()) {
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginResponse(false, null, null, null));
                    }

                    User user = found.get();
                    Set<String> roles = user.getRoles().stream().map(Enum::name).collect(Collectors.toSet());

                    String access = jwtUtils.generateAccessToken(user.getUsername(), roles);
                    String refresh = jwtUtils.generateRefreshToken(user.getUsername());

                    tokenService.storeTokens(user, access, refresh);

                    return ResponseEntity.ok(new LoginResponse(true, userResp, access, refresh));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new LoginResponse(false, null, null, null)));
    }

    public record SimpleError(String error) {}
}
