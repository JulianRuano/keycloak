package com.security.keycloak.infraestructure.output.keycloakAdapter;

import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;


import com.security.keycloak.application.output.IKeycloakTokenOutputPort;
import com.security.keycloak.application.output.IRealmResourceOutputPort;
import com.security.keycloak.domain.models.Auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Adaptador para la gestión de Keycloak utilizando el cliente de administración de Keycloak.
 * Implementa las interfaces IRealmResourceOutputPort y IKeycloakTokenOutputPort.
 */
@Component
public class KeycloakProvider implements IRealmResourceOutputPort , IKeycloakTokenOutputPort{

    @Value("${keycloak.server.url}")
    private String KEYCLOAK_SERVER_URL;

    @Value("${keycloak.realm.name}")
    private String REALM_NAME;

    @Value("${keycloak.realm.master}")
    private String REALM_MASTER;

    @Value("${keycloak.admin}")
    private String ADMIN_CLI;

    @Value("${keycloak.user.console}")
    private String USER_CONSOLE;

    @Value("${keycloak.password}")
    private String PASSWORD_CONSOLE;

    @Value("${keycloak.client.secret}")
    private String CLIENT_SECRET;
   
    @Value("${jwt.token.url}")
    private String tokenUrl; 

    @Value("${jwt.auth.converter.resource-id}")
    private String CLIENT_ID;

    /**
     * Obtiene el recurso del Realm de Keycloak.
     *
     * @return el recurso del Realm de Keycloak
     */
    @Override
    public RealmResource getRealmResource() {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK_SERVER_URL)
                .realm(REALM_MASTER)
                .username(USER_CONSOLE)
                .password(PASSWORD_CONSOLE)
                .clientId(ADMIN_CLI)
                .clientSecret(CLIENT_SECRET)
                .resteasyClient(new ResteasyClientBuilderImpl()
                        .connectionPoolSize(10)
                        .build())
                .build();
        
        return keycloak.realm(REALM_NAME); 
    }

    /**
     * Obtiene el recurso de usuarios del Realm de Keycloak.
     *
     * @return el recurso de usuarios del Realm de Keycloak
     */
    @Override
    public UsersResource getUserResource() {
        RealmResource realmResource = getRealmResource();
        return realmResource.users();
    }

    /**
     * Obtiene el token JWT de Keycloak.
     *
     * @param auth los datos de autenticación
     * @return el token JWT
     */
    @Override
    public String getToken(Auth auth) {
         // Crear un MultiValueMap para almacenar los parámetros del formulario de solicitud
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();

        // Agregar los parámetros requeridos al formulario
        formData.add("client_id", CLIENT_ID);
        formData.add("grant_type", "password");
        formData.add("username", auth.getUsername());
        formData.add("password", auth.getPassword());
        formData.add("client_secret", CLIENT_SECRET);
        
        // Crear los encabezados HTTP y establecer el tipo de contenido a application/x-www-form-urlencoded
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Enviar una solicitud POST a la URL del token y recibir la respuesta en una entidad ResponseEntity
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        // Devolver el cuerpo de la respuesta, que contiene el token de autenticación
        ResponseEntity<String> response = new RestTemplate().postForEntity(tokenUrl, requestEntity, String.class);

        return response.getBody();
     
    }

    
}