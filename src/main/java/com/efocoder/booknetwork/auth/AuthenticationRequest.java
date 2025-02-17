package com.efocoder.booknetwork.auth;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthenticationRequest {
    @NotEmpty(message = "Email required")
    @NotBlank(message = "Email required")
    @Email(message = "Email is not valid")
    private String email;

    @NotEmpty(message = "password required")
    @NotBlank(message = "password required")
    @Size(min=8)
    private  String password;
}
