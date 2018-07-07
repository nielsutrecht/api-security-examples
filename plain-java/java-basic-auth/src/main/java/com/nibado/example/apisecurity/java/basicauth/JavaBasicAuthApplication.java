package com.nibado.example.apisecurity.java.basicauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JavaBasicAuthApplication {
    public static void main(String... argv) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/secure", JavaBasicAuthApplication::handleSecure);
        server.createContext("/open", JavaBasicAuthApplication::handleOpen);
        server.setExecutor(null);

        System.out.println("Server started");

        server.start();
    }

    public static void handleOpen(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        writeResponse(ex, 200, "Open endpoint");
    }

    public static void handleSecure(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        if (ex.getRequestHeaders().containsKey("Authorization")) {
            String[] userPass = getUserAndPassword(ex);

            System.out.printf("Login from user %s with pass %s\n", userPass[0], userPass[1]);
            System.out.println(ex.getPrincipal().getName());
            System.out.println(ex.getPrincipal().getUsername());

            writeResponse(ex, 200, "Secure endpoint");
        } else {
            ex.getResponseHeaders().add("WWW-Authenticate", "Basic realm=MY_REALM");
            writeResponse(ex, 401, "Not authorized");
        }
    }

    private static String[] getUserAndPassword(HttpExchange ex) throws IOException {
        String headerValue = ex.getRequestHeaders().getFirst("Authorization");

        if(!headerValue.startsWith("Basic ")) {
            throw new IOException("Only HTTP Basic Auth is supported");
        }

        return new String(
            Base64.getDecoder().decode(headerValue.substring(6)), UTF_8)
            .split(":", 2);
    }

    private static void writeResponse(HttpExchange ex, int status, String message) throws IOException {
        byte[] response = message.getBytes(UTF_8);
        ex.sendResponseHeaders(status, response.length);
        try(OutputStream os = ex.getResponseBody()) {
            os.write(response);
        }
    }
}
