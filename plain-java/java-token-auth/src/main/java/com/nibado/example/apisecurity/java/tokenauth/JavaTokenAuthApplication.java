package com.nibado.example.apisecurity.java.tokenauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JavaTokenAuthApplication {
    private static final Map<UUID, String> tokenToUserMap = new HashMap<>();

    public static void main(String... argv) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/login", JavaTokenAuthApplication::handleLogin);
        server.createContext("/secure", JavaTokenAuthApplication::handleSecure);
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

        UUID token = UUID.randomUUID();
        tokenToUserMap.put(token, userPass.get("user"));
        writeResponse(ex, 200, "Token: " + token);
    }

    public static void handleSecure(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        Optional<UUID> token = getToken(ex);

        if(token.isPresent()) {
            System.out.printf("Token access from user %s with token %s\n", tokenToUserMap.get(token.get()), token.get());

            writeResponse(ex, 200, "Welcome back " + tokenToUserMap.get(token.get()));
        } else {
            ex.getResponseHeaders().add("WWW-Authenticate", "Bearer");
            writeResponse(ex, 401, "Not authorized");
        }
    }

    private static Optional<UUID> getToken(HttpExchange ex) {
        String header = ex.getRequestHeaders().getFirst("Authorization");

        if(header == null || !header.startsWith("Bearer")) {
            return Optional.empty();
        }

        return Optional.of(UUID.fromString(header.substring(7)));
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
