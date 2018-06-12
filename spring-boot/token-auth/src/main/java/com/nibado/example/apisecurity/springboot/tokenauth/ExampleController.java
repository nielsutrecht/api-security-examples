package com.nibado.example.apisecurity.springboot.tokenauth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {
    private final UserRepository userRepository;

    public ExampleController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/not-secured")
    public Response notSecuredEndpoint() {
        return new Response("This is the not-secured end-point");
    }

    @GetMapping("/login")
    public ResponseEntity<LoginResponse> loginEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof AnonymousAuthenticationToken)) {
            return ResponseEntity.ok(new LoginResponse(userRepository.login((UserDetails) auth.getPrincipal())));
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @GetMapping("/secured")
    public Response securedEndpoint() {
        return new Response("This is the secured end-point");
    }

    @GetMapping("/admin/secured")
    public Response securedAdminEndpoint() {
        return new Response("This is the secured admin end-point");
    }


    private static class Response {
        public final String message;

        public Response(String message) {
            this.message = message;
        }
    }

    private static class LoginResponse {
        public final String token;

        public LoginResponse(String token) {
            this.token = token;
        }
    }
}
