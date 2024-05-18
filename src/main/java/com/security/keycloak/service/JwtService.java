package com.security.keycloak.service;

import java.util.List;

//import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


@Service
public class JwtService {

//   @Value("${jwt.secret}")
//    private String SECRET_KEY;

    public static void decodeJwt(String token) {
        Claims claims = Jwts.parser()
                .parseClaimsJws(token)
                .getBody();

        // Obtener roles
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("resource_access.microsservices_client.roles");
        System.out.println("Roles: " + roles);

        // Obtener username
        String username = claims.get("preferred_username", String.class);
        System.out.println("Username: " + username);

        // Obtener sub
        String sub = claims.getSubject();
        System.out.println("Sub: " + sub);
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnFZOtnknR7gWw/1rllOWil2nthWM/0eOxq3DwqcevIpLErPL3Ao7nsQxB+7sOtYnpxVwNMBHbcZmpnucVEHYSXDA6lQu68uliWnq98LvxW8dCrJNQ1la+nyNbSqHJxfWlJrFgvt9vUf35gsA6mOHKD2WTV8wwG8fHhhXwHe9H2zRB2zaQZQDOzcZXTZCm7z4MTamFB5pL12x63W9aJIaF3+jv5hQhfdM+zqsjo5nGFVd/RTL1132dQr1d9OhxBbM9wq7PXCPrr6Y8umxO1gpJnKlkwmyWR8CJlBieJ1Z2xjdPg0AKxJYY8QX8iSPahiaNtT6nLCBDeh8ntBIQMpiswIDAQAB")
                .parseClaimsJws(token)
                .getBody();

        System.err.println("Claims: " + claims);

        // Obtener username
        String username = claims.get("preferred_username", String.class);
        return username;
    }
    
}