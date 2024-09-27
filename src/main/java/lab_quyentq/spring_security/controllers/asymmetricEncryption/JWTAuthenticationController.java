package lab_quyentq.spring_security.controllers.asymmetricEncryption;

import jakarta.servlet.http.HttpServletRequest;
import lab_quyentq.spring_security.services.security.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequestMapping("/api/boi-thuong")
public class JWTAuthenticationController {
    public CreateToken createToken;

    public ValidateToken validateToken;

    public JWTAuthenticationController(CreateToken createToken, ValidateToken validateToken) {
        this.validateToken = validateToken;
        this.createToken = createToken;
    }

    @GetMapping("/get-token")
    public String createToken() throws Exception {
        return createToken.doCreateToken();
    }

    @GetMapping("/create-keyPair")
    public List<HashMap<String, String>> createKeyPair() throws Exception {
        return GenerateKeyPair.createKeyPair();
    }

    @GetMapping("/validate-token")
    public String validateToken(HttpServletRequest request) throws Exception {
        return validateToken.validateToken(request);
    }
}
