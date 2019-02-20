package oauth.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ResourceController {

    @GetMapping("/")
    public String index(){
        return "Index. Permit All.";
    }

    @GetMapping("/user")
    public String user(){
        return "User access";
    }

    @GetMapping("/admin")
    public String admin(){
        return "Admin access";
    }
}
