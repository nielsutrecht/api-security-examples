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
import java.util.UUID;

@Component
public class UserRepository implements UserDetailsService {
    private final Map<String, UserDetails> users = new HashMap<>();
    private final Map<String, UserDetails> tokenMap = new HashMap<>();

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        if(!users.containsKey(s)) {
            throw new UsernameNotFoundException(s);
        }
        UserDetails user = users.get(s);
        return new User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities());
    }

    public UserDetails loadByToken(String s) throws UsernameNotFoundException {
        if(!tokenMap.containsKey(s)) {
            throw new UsernameNotFoundException(s);
        }
        return tokenMap.get(s);
    }

    public String login(UserDetails details) {
        String token = UUID.randomUUID().toString();
        tokenMap.put(token, details);

        return token;
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
