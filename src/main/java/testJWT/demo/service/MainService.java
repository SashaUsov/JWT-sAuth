package testJWT.demo.service;

import org.springframework.stereotype.Service;
import testJWT.demo.domain.ApplicationUser;
import testJWT.demo.domain.dto.CreateUserModel;
import testJWT.demo.repo.UserRepo;

@Service
public class MainService {

    private final UserRepo userRepo;

    public MainService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    public String getGreeting() {

        return "You could and created JWT authentication!";
    }

    public ApplicationUser create(CreateUserModel userModel) {

        ApplicationUser applicationUser = new ApplicationUser();

        applicationUser.setUserName(userModel.getUserName());
        applicationUser.setPassword(userModel.getPassword());

        return userRepo.save(applicationUser);
    }
}
