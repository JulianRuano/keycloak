package com.security.keycloak.infraestructure.output.keycloakAdapter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.security.keycloak.application.output.IAuthOutputPort;
import com.security.keycloak.domain.models.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * Adaptador para la autenticacion
 * Implementa la interfaz IAuthOutputPort
 */
@Component
public class AuthAdapter implements IAuthOutputPort{


    @Value("${jwt.public.key}")
    private  String publicKeyString;

    /**
     * Obtiene el usuario actual basado en el token de autorización JWT.
     *
     * @param authorizationHeader El encabezado de autorización que contiene el token JWT.
     * @return Un objeto User que representa al usuario autenticado.
     * @throws NoSuchAlgorithmException Si el algoritmo de generación de claves no es válido.
     * @throws InvalidKeySpecException Si la especificación de la clave es inválida.
     */
    @Override
    public User getCurrentUser(String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String jwt = null;
        // Verifica si el encabezado de autorización contiene un token Bearer
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
        }

        if (jwt != null) {
            PublicKey publicKey = getPublicKey(publicKeyString);
            Claims claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt).getBody();
            @SuppressWarnings("unchecked")

            // Construye un objeto User basado en los claims del token JWT
            User user = User.builder()
            .id(claims.get("sub").toString())
            .username(claims.get("preferred_username").toString())
            .email(claims.get("email").toString())
            .firstName(claims.get("given_name").toString())
            .lastName(claims.get("family_name").toString())
            .roles((List<String>) ((Map<String, Object>) ((Map<String, Object>) claims.get("resource_access")).get("microservices_client")).get("roles"))
            .build();

            return user;
        } else {
            return null;
        }
    }

 /**
     * Obtiene la clave pública a partir de su representación en cadena.
     *
     * @param publicKeyString La cadena que representa la clave pública en formato Base64.
     * @return La clave pública correspondiente.
     * @throws NoSuchAlgorithmException Si el algoritmo de generación de claves no es válido.
     * @throws InvalidKeySpecException Si la especificación de la clave es inválida.
     */
    private PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Decodifica la clave pública desde Base64
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        // Crea una especificación de clave con el formato X509
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        // Obtiene una instancia del KeyFactory para el algoritmo RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // Genera la clave pública a partir de la especificación de clave
        return keyFactory.generatePublic(keySpec);
    }
    
    
}
