package com.nibado.example.apisecurity.springboot.basicauth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class ApplicationTest {
    @Autowired
    private MockMvc mvc;

    @Test
    public void getUnsecured() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/not-secured")).andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("This is the not-secured end-point")));
    }

    @Test
    @WithMockUser
    public void getUnsecured_WithUser() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/not-secured"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("This is the not-secured end-point")));
    }

    @Test
    @WithMockUser
    public void getSecured() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/secured"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("This is the secured end-point")));
    }

    @Test
    public void getSecured_NoUser() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/secured"))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", is("Unauthorised, please provide basic auth username + password")));
    }

    @Test
    @WithMockUser(roles="ADMIN")
    public void getSecuredAdmin() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/admin/secured"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("This is the secured admin end-point")));
    }

    @Test
    @WithMockUser
    public void getSecuredAdmin_NormalUser() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/admin/secured"))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

}