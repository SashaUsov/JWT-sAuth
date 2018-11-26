package testJWT.demo.domain.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateUserModel {

    private String userName;

    private String password;
}