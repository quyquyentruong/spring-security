package lab_quyentq.spring_security.services.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@Service
public class ValidateToken {
    @Value("${publicKey.Path}")
    public String publicKeyPath;

    @Autowired
    public PublicKeyLoader publicKeyLoader;

    public String validateToken(HttpServletRequest request) throws Exception {
        try {
            PublicKey publicKey = publicKeyLoader.loadPublicKeyFromFile(publicKeyPath);
            String bearerToken = request.getHeader("Authorization");
            String token = "";

            if (bearerToken.startsWith("Bearer ")) {
                token = bearerToken.substring(7); // Remove the first 7 characters ("Bearer ")
            } else {
                throw new Exception("Bad Request");
            }

            boolean isValid = validateToken(token, publicKey);

            if (isValid) {
                return "Token hợp lệ!";
            } else {
                return "Token không hợp lệ!";
            }
        } catch (Exception exception) {
            throw new Exception(exception);
        }
    }

    public static boolean validateToken(String token, PublicKey publicKey) {
        try {
            // Khởi tạo thuật toán RSA với public key
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

            // Xác thực token với public key
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build();

            // Decode token
            DecodedJWT jwt = verifier.verify(token);

            // Nếu không có lỗi xảy ra thì token hợp lệ
            return true;
        } catch (Exception e) {
            // Nếu có lỗi xảy ra trong quá trình xác thực
            e.printStackTrace();
            return false;
        }
    }
}
