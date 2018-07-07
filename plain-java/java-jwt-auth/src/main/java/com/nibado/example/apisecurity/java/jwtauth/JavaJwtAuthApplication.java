package com.nibado.example.apisecurity.java.jwtauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.MacProvider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JavaJwtAuthApplication {
    private static final Key KEY = MacProvider.generateKey();

    public static void main(String... argv) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/login", JavaJwtAuthApplication::handleLogin);
        server.createContext("/secure", JavaJwtAuthApplication::handleSecure);

        server.setExecutor(null);

        System.out.println("Server started");

        server.start();
    }

    public static void handleLogin(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        if(!ex.getRequestMethod().equals("POST")) {
            writeResponse(ex, 400, "Only POST supported");
            return;
        }

        Map<String, String> userPass = getFormData(ex);
        System.out.printf("Login from user %s with pass %s\n", userPass.get("user"), userPass.get("password"));

        Date expires = Date.from(ZonedDateTime.now().plusMinutes(15).toInstant());

        String compactJws = Jwts.builder()
                .setSubject(userPass.get("user"))
                .setIssuedAt(new Date())
                .setExpiration(expires)
                .signWith(SignatureAlgorithm.HS512, KEY)
                .compact();

        writeResponse(ex, 200, "Token: " + compactJws);
    }

    public static void handleSecure(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        Optional<Claims> token = getClaims(ex);

        if(token.isPresent()) {
            System.out.printf("JWT access from user %s\n", token.get().getSubject());

            writeResponse(ex, 200, "Welcome back " + token.get().getSubject());
        } else {
            ex.getResponseHeaders().add("WWW-Authenticate", "Bearer");
            writeResponse(ex, 401, "Missing or invalid token");
        }
    }

    private static Optional<Claims> getClaims(HttpExchange ex) {
        String header = ex.getRequestHeaders().getFirst("Authorization");

        if(header == null || !header.startsWith("Bearer")) {
            return Optional.empty();
        }

        try {
            Jws<Claims> jws = Jwts.parser().setSigningKey(KEY).parseClaimsJws(header.substring(7));

            return Optional.of(jws.getBody());

        } catch (SignatureException e) {
            return Optional.empty();
        }
    }

    private static Map<String, String> getFormData(HttpExchange ex) throws IOException {
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(ex.getRequestBody()))) {
            return buffer.lines()
                    .flatMap(l -> Stream.of(l.split("&")))
                    .map(s -> s.split("="))
                    .collect(Collectors.toMap(a -> a[0], a -> a[1]));
        }
    }

    private static void writeResponse(HttpExchange ex, int status, String message) throws IOException {
        byte[] response = message.getBytes(UTF_8);
        ex.sendResponseHeaders(status, response.length);
        try(OutputStream os = ex.getResponseBody()) {
            os.write(response);
        }
    }
}
