package com.nibado.example.apisecurity.java.oauth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.egit.github.core.User;
import org.eclipse.egit.github.core.client.GitHubClient;
import org.eclipse.egit.github.core.service.UserService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JavaOAuthApplication {
    private static Properties properties = new Properties();
    private static UUID state = UUID.randomUUID();

    public static void main(String... argv) throws Exception {
        properties.load(JavaOAuthApplication.class.getResourceAsStream("/secrets.properties"));

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/oauth", JavaOAuthApplication::handleOAuth);
        server.createContext("/connect2", JavaOAuthApplication::handleConnect);
        server.setExecutor(null);

        System.out.println("Server started");

        server.start();
    }

    public static void handleConnect(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        String url = "https://github.com/login/oauth/authorize?" +
                "client_id=" +
                properties.getProperty("client-id") +
                "&redirect_uri=" +
                URLEncoder.encode("http://localhost:8080/oauth", "utf-8") +
                "&scope=user" +
                "&allow_signup=false" +
                "&state=" +
                state;

        ex.getResponseHeaders().add("Location", url);

        writeResponse(ex, 301, "Open endpoint");
    }

    public static void handleOAuth(HttpExchange ex) throws IOException {
        System.out.printf("%s %s\n", ex.getRequestMethod(), ex.getRequestURI());

        Map<String, String> queryParams = getQueryParams(ex);

        Map<String, String> postData = new HashMap<>();
        postData.put("client_id", properties.getProperty("client-id"));
        postData.put("client_secret", properties.getProperty("client-secret"));
        postData.put("code", queryParams.get("code"));
        postData.put("state", state.toString());

        Map<String, String> responseData = doPost("https://github.com/login/oauth/access_token", postData);

        User user = getUser(responseData.get("access_token"));

        writeResponse(ex, 200, String.format("Welcome %s", user.getName()));
    }

    private static Map<String, String> getQueryParams(HttpExchange ex) {
        return Stream.of(ex.getRequestURI().getQuery().split("&"))
                .map(s -> s.split("="))
                .collect(Collectors.toMap(a -> a[0], a -> a[1]));
    }

    private static Map<String, String> doPost(String url, Map<String, String> postData) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();

        byte[] postDataBytes = postData.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"))
                .getBytes(StandardCharsets.UTF_8);

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Content-Length", String.valueOf(postDataBytes.length));
        conn.setDoOutput(true);
        conn.getOutputStream().write(postDataBytes);
        conn.getOutputStream().flush();

        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            return buffer.lines()
                    .flatMap(l -> Stream.of(l.split("&")))
                    .map(s -> s.split("="))
                    .collect(Collectors.toMap(a -> a[0], a -> a[1]));
        }
    }

    public static User getUser(String token) throws IOException {
        GitHubClient client = new GitHubClient();
        client.setOAuth2Token(token);

        return new UserService(client).getUser();
    }

    private static String encode(String s) {
        try {
            return URLEncoder.encode(s, "utf-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeResponse(HttpExchange ex, int status, String message) throws IOException {
        byte[] response = message.getBytes(UTF_8);
        ex.sendResponseHeaders(status, response.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(response);
        }
    }
}
