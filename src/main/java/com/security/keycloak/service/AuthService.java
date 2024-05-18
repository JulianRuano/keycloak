package com.security.keycloak.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class AuthService {

    @Autowired
    private  JwtService jwtService;

     //obtener usuaruio del token
     public String getCurrentUser(String authorizationHeader) {
        String token = authorizationHeader.substring(7); 
        String username = jwtService.getUsernameFromToken(token);
        
        return username;  
    }


}
