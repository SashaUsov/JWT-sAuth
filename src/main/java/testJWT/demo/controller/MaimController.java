package testJWT.demo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import testJWT.demo.domain.ApplicationUser;
import testJWT.demo.domain.dto.CreateUserModel;
import testJWT.demo.service.MainService;

@RestController
@RequestMapping("main")
class MainController {

    private final MainService mainService;

    public MainController(MainService mainService) {
        this.mainService = mainService;
    }

    @GetMapping("greeting")
    public String getGreeting() {

        return mainService.getGreeting();
    }

    @PostMapping("registration")
    @ResponseStatus(HttpStatus.CREATED)
    public ApplicationUser create(@RequestBody CreateUserModel userModel) {

        return mainService.create(userModel);
    }
}