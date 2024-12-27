package com.efocoder.booknetwork.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
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
public class RegistrationRequest {
    @NotEmpty(message = "first name required")
    @NotBlank(message = "first name required")
    @JsonProperty("first_name")
    private String firstName;

    @NotEmpty(message = "last name required")
    @NotBlank(message = "last name required")
    @JsonProperty("last_name")
    private String lastName;

    @NotEmpty(message = "Email required")
    @NotBlank(message = "Email required")
    @Email(message = "Email is not valid")
    private String email;

    @NotEmpty(message = "password required")
    @NotBlank(message = "password required")
    @Size(min=8)
    private  String password;
}
