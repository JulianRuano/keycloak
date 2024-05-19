package com.security.keycloak.dto;

import java.util.List;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@Value
@RequiredArgsConstructor
@Builder
public class UserResponse{

    String id;
    String username;
    String email;
    String firstName;
    String lastName;

    List<String> roles;

}
