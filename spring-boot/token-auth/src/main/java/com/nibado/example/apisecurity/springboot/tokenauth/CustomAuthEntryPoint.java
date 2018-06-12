package com.nibado.example.apisecurity.springboot.tokenauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

import static com.nibado.example.apisecurity.springboot.tokenauth.WebSecurityConfig.REALM;

public class CustomAuthEntryPoint extends BasicAuthenticationEntryPoint {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public void commence(final HttpServletRequest request,
                         final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException, ServletException {
        //Authentication failed, send error response.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.addHeader("WWW-Authenticate", "Basic realm=" + getRealmName() + "");

        PrintWriter writer = response.getWriter();
        writer.println( MAPPER.writeValueAsString(new ErrorResponse()));
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        setRealmName(REALM);
        super.afterPropertiesSet();
    }

    public static class ErrorResponse {
        public final String message = "Unauthorised, please provide basic auth username + password";
    }
}