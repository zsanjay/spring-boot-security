package com.example.demo.jwt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtUserStore {
    private Map<String, List<String>> tokenMap = new HashMap<>();

    public void addToken(String username , String token) {

        if(tokenMap.containsKey(username)) {
            List<String> tokens = tokenMap.get(username);
            int size = tokens.size();
            if(size == 5) {
                invalidateFirstIssuedToken(tokens.get(0));
                tokens.remove(0);
            }
            tokens.add(token);
            tokenMap.put(username , tokens);
        } else {
            List<String> tokens = new ArrayList<>();
            tokens.add(token);
            tokenMap.put(username, tokens);
        }
    }

    private void invalidateFirstIssuedToken(String token) {

    }
}
