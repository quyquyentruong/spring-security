package lab_quyentq.spring_security.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class JwtTokenCreator {
    // Phương thức để tải private key từ file
    public static PrivateKey loadPrivateKeyFromFile(String filename) throws Exception {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();

        // Loại bỏ phần header và footer của private key PEM
        String privateKeyPEM = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // Giải mã và tạo private key từ PKCS8EncodedKeySpec
        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    // Phương thức tạo JWT token với private key
    public static String createToken(String privateKeyPath) throws Exception {
        // Tải private key từ file
        PrivateKey privateKey = loadPrivateKeyFromFile(privateKeyPath);

        // Khởi tạo thuật toán ký với private key
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) null, (RSAPrivateKey) privateKey);

        // Tạo token với thông tin cần thiết
        String token = JWT.create()
                .withIssuer("auth0")
                .withSubject("user123")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000))  // Token sẽ hết hạn sau 1 giờ
                .sign(algorithm);

        return token;
    }

    public static void main(String[] args) throws Exception {
        // Đường dẫn tới file privateKey.pem
        String token = createToken("path/to/privateKey.pem");
        System.out.println("Generated JWT Token: " + token);
    }
}
