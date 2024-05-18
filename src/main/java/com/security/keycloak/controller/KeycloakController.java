package com.security.keycloak.controller;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.keycloak.dto.UserDTO;
import com.security.keycloak.service.AuthService;
import com.security.keycloak.service.IKeycloakService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@RestController
@RequestMapping("/keycloak")
@PreAuthorize("hasRole('admin_client')")
public class KeycloakController {

    @Autowired
    private IKeycloakService keycloakService;

    @Autowired
    private AuthService authService;


    @GetMapping("/users")
    public ResponseEntity<?> findAllUsers() {
        return ResponseEntity.ok(keycloakService.findAllUsers());
    }

    @GetMapping("/users/{username}")
    public ResponseEntity<?> findUserByUsername(@PathVariable String username) {
        return ResponseEntity.ok(keycloakService.findUserByUsername(username));
    }

    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody UserDTO userDTO) throws URISyntaxException {
        String response = keycloakService.createUser(userDTO);
        return ResponseEntity.created(new URI("/keycloak/create")).body(response);
    }

    @PutMapping("/update/{username}")
    public ResponseEntity<?> updateUser(@PathVariable String username, @RequestBody UserDTO userDTO) {
        keycloakService.updateUser(username, userDTO);
        return ResponseEntity.ok("User updated successfully");
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        keycloakService.deleteUser(userId);
        return ResponseEntity.ok("User deleted successfully");
    }

       //obtener usuaruio del token por header
       @GetMapping(value = "getCurrentUser")
       public String  getCurrentUser(@RequestHeader("Authorization") String authorizationHeader)
       {
          return authService.getCurrentUser(authorizationHeader);
       }

    @GetMapping("/username")
    public String obtenerUsername(@RequestHeader("Authorization") String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
