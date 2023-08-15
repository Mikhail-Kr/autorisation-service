package mkr.infra.web;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/front-api/v1/test-authorization")
@RequiredArgsConstructor
public class AuthorizationTestController {

    @GetMapping("/with-role")
    // write here your role
    @PreAuthorize("hasAnyRole('ADMIN')")
    public String testWithAuthorizationWithExistingRole() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }

    @GetMapping("/not-exist-role")
    // must throw exception 403 code
    @PreAuthorize("hasRole('123')")
    public String testWithAuthorizationWithNotExistingRole() {
        return "it works with other role";
    }

    @GetMapping("/anonymous")
    public String testWithoutAuthorization() {
        return "it works without security";
    }
}
