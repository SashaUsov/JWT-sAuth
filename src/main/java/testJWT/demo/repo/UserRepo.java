package testJWT.demo.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import testJWT.demo.domain.ApplicationUser;

public interface UserRepo extends JpaRepository<ApplicationUser, Long> {

}
