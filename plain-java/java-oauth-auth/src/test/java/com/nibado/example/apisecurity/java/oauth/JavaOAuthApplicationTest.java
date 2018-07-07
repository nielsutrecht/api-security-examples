package com.nibado.example.apisecurity.java.oauth;

import org.eclipse.egit.github.core.User;
import org.junit.jupiter.api.Test;

class JavaOAuthApplicationTest {

    @Test
    void getUser() throws Exception {
        User user = JavaOAuthApplication.getUser("0e9d3ef34b999e374b8bf688e0c750ade0d32f07");
        System.out.println(user.getName());
    }
}
