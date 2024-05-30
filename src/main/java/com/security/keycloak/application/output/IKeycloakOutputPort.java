package com.security.keycloak.application.output;

import java.util.List;

import com.security.keycloak.domain.models.User;
import com.security.keycloak.infraestructure.input.rest.data.response.UserResponse;

public interface IKeycloakOutputPort {
    List<UserResponse> findAllUsers();
    List<UserResponse> findUserByUsername(String username);
    String createUser(User user);
    void deleteUser(String userId);
    void updateUser(String userId, User user);
}
