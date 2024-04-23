package com.security.keycloak.service;

import java.util.List;

import org.keycloak.representations.idm.UserRepresentation;

import com.security.keycloak.dto.UserDTO;

public interface IKeycloakService {

    List<UserRepresentation> findAllUsers();
    List<UserRepresentation> findUserByUsername(String username);
    String createUser(UserDTO userDTO);
    void deleteUser(String userId);
    void updateUser(String userId, UserDTO userDTO);
    
}
