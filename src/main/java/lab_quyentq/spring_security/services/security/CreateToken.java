package lab_quyentq.spring_security.services.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

@Service
public class CreateToken {
    @Value("${privateKey.Path}")
    public String privateKeyPath;

    public String doCreateToken() throws Exception {
        RSAPrivateKey privateKey = PrivateKeyLoader.loadPrivateKeyFromFile(privateKeyPath);

        // Khởi tạo thuật toán ký với private key
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);

        // Tạo token với thông tin cần thiết
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject("user123")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000))  // Token sẽ hết hạn sau 1 giờ
                .sign(algorithm);

        return token;
    }
}
