package com.nibado.example.apisecurity.springboot.tokenauth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {
    @GetMapping("/not-secured")
    public Response notSecuredEndpoint() {
        return new Response("This is the not-secured end-point");
    }

    @GetMapping("/secured")
    public Response securedEndpoint() {
        return new Response("This is the secured end-point");
    }

    @GetMapping("/admin/secured")
    public Response securedAdminEndpoint() {
        return new Response("This is the secured admin end-point");
    }

    @GetMapping("/secured-annotation")
    @PreAuthorize("hasRole('ADMIN')")
    public Response securedAnnotation() {
        return new Response("This is the secured with annotation admin end-point");
    }

    private static class Response {
        public final String message;

        public Response(String message) {
            this.message = message;
        }
    }
}
