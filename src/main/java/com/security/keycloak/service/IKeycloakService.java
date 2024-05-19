package com.security.keycloak.service;

import java.util.List;

import com.security.keycloak.dto.UserDTO;
import com.security.keycloak.dto.UserResponse;

public interface IKeycloakService {

    List<UserResponse> findAllUsers();
    List<UserResponse> findUserByUsername(String username);
    String createUser(UserDTO userDTO);
    void deleteUser(String userId);
    void updateUser(String userId, UserDTO userDTO);
}
