package testJWT.demo.domain;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@Entity
@Table(name = "user_table")
public class ApplicationUser {

    @Column(name = "user_name")
    String userName;

    @Column(name = "password")
    String password;

    @Column(name = "id", updatable = false, nullable = false)
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "usr_sequence")
    Long id;
}