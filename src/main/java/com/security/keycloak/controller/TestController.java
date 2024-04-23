package com.security.keycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
public class TestController {
    
    @GetMapping("/testAdmin")
    @PreAuthorize("hasRole('admin_client_role')")
    public String test() {
        return "Test for Admin";
    }

    @GetMapping("/testUser")
    @PreAuthorize("hasRole('user_client_role') or hasRole('admin_client_role')")
    public String testUser() {
        return "Test for User";
    }
}
