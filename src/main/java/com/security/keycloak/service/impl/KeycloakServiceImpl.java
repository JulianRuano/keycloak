package com.security.keycloak.service.impl;

import java.util.List;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import com.security.keycloak.dto.UserDTO;
import com.security.keycloak.service.IKeycloakService;
import com.security.keycloak.util.KeycloakProvider;

import jakarta.ws.rs.core.Response;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class KeycloakServiceImpl implements IKeycloakService{

    /**
     * Metodo para obtener todos los usuarios de Keycloak
     * @return List<UserRepresentation>
     */
    @Override
    public List<UserRepresentation> findAllUsers() {
        return KeycloakProvider.getRealmResource()
            .users()
            .list();
    }

    /**
     * Metodo para obtener un usuario por su id
     * @param userId id del usuario
     * @return List<UserRepresentation>
     */
    @Override
    public List<UserRepresentation> findUserByUsername(String username) {
        return KeycloakProvider.getRealmResource()
            .users()
            .searchByUsername(username, true);
    }

    /**
     * Metodo para crear un usuario
     * @param userDTO datos del usuario
     * @return String
     */
    @Override
    public String createUser(@NonNull UserDTO userDTO) {
        int status = 0;
        UsersResource usersResource = KeycloakProvider.getUserResource();

        UserRepresentation user = new UserRepresentation();

        user.setUsername(userDTO.getUsername());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEmail(userDTO.getEmail());
        user.setEnabled(true);
        user.setEmailVerified(true);

        Response response = usersResource.create(user);
        status = response.getStatus();

        if(status == 201) {
            String path = response.getLocation().getPath();
            String userId = path.substring(path.lastIndexOf('/') + 1);
            
            CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
            credentialRepresentation.setTemporary(false);
            credentialRepresentation.setType(OAuth2Constants.PASSWORD);
            credentialRepresentation.setValue(userDTO.getPassword());

            usersResource.get(userId).resetPassword(credentialRepresentation);

            RealmResource realmResource = KeycloakProvider.getRealmResource();

            List<RoleRepresentation> roles = null;

            if(userDTO.getRoles() == null || userDTO.getRoles().isEmpty()) {
                roles = List.of(realmResource.roles().get("user").toRepresentation());       
            }else{
                roles = realmResource
                    .roles()
                    .list()
                    .stream()
                    .filter(role -> userDTO.getRoles()
                        .stream()
                        .anyMatch(roleName -> roleName.equalsIgnoreCase(role.getName())))
                    .toList();
            }

            realmResource.users()
                .get(userId)
                .roles()
                .realmLevel()
                .add(roles);

            return "User created with username: " + user.getUsername() + " successfully.";

        } else if(status == 409) {
            log.error("User with username: {} already exists.", user.getUsername());
            return "User with username: " + user.getUsername() + " already exists.";
        } else {
            log.error("Error creating user with username: {}. Status code: {}", user.getUsername(), status);
            return "Error creating user with username: " + user.getUsername() + ". Status code: " + status;    
        }
    }

    /**
     * Metodo para eliminar un usuario
     * @param userId id del usuario
     */
    @Override
    public void deleteUser(String userId) {
        KeycloakProvider.getUserResource()
            .get(userId)
            .remove();
    }

    /**
     * Metodo para actualizar un usuario
     * @param userId id del usuario
     * @param userDTO datos del usuario
     */
    @Override
    public void updateUser(String userId,@NonNull UserDTO userDTO) {
        
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setTemporary(false);
        credentialRepresentation.setType(OAuth2Constants.PASSWORD);
        credentialRepresentation.setValue(userDTO.getPassword());

        UserRepresentation user = new UserRepresentation();

        user.setUsername(userDTO.getUsername());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEmail(userDTO.getEmail());
        user.setEnabled(true);
        user.setEmailVerified(true);
        user.setCredentials(List.of(credentialRepresentation));

        UserResource userResource = KeycloakProvider.getUserResource().get(userId);
        userResource.update(user);
    }
}
