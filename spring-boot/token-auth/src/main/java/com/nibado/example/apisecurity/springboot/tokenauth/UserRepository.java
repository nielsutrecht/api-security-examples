package com.nibado.example.apisecurity.springboot.tokenauth;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

@Component
public class UserRepository implements UserDetailsService {
    private final Map<String, UserDetails> users = new HashMap<>();

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        if(!users.containsKey(s)) {
            throw new UsernameNotFoundException(s);
        }
        return users.get(s);
    }

    public void addUser(UserDetails user) {
        users.put(user.getUsername(), user);
    }

    @PostConstruct
    public void init() {
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        addUser(User.withUsername("john").password("secret").roles("USER").passwordEncoder(encoder::encode).build());
        addUser(User.withUsername("jane").password("supersecret").roles("ADMIN").passwordEncoder(encoder::encode).build());
    }
}
