package com.security.keycloak.service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


@Service
public class AuthService {

     //obtener usuaruio del token
     public String getCurrentUser(String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException{
          String jwt = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
        }

        if (jwt != null) {
            String publicKeyString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnFZOtnknR7gWw/1rllOWil2nthWM/0eOxq3DwqcevIpLErPL3Ao7nsQxB+7sOtYnpxVwNMBHbcZmpnucVEHYSXDA6lQu68uliWnq98LvxW8dCrJNQ1la+nyNbSqHJxfWlJrFgvt9vUf35gsA6mOHKD2WTV8wwG8fHhhXwHe9H2zRB2zaQZQDOzcZXTZCm7z4MTamFB5pL12x63W9aJIaF3+jv5hQhfdM+zqsjo5nGFVd/RTL1132dQr1d9OhxBbM9wq7PXCPrr6Y8umxO1gpJnKlkwmyWR8CJlBieJ1Z2xjdPg0AKxJYY8QX8iSPahiaNtT6nLCBDeh8ntBIQMpiswIDAQAB";
            PublicKey publicKey = getPublicKey(publicKeyString);
            Claims claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt).getBody();
            String username = claims.get("preferred_username", String.class);
            return username;
        } else {
            return "Token JWT no válido";
        }
    }

    private PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

}
