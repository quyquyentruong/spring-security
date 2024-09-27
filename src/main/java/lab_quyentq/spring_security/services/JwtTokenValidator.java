package lab_quyentq.spring_security.services;

import io.jsonwebtoken.Jwts;

import java.security.PublicKey;

public class JwtTokenValidator {

    public static boolean validateToken(String token, PublicKey publicKey) {
        try {
            // Giải mã và xác thực chữ ký JWT bằng khóa công khai
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);
            return true; // Token hợp lệ
        } catch (Exception e) {
            e.printStackTrace();
            return false; // Token không hợp lệ
        }
    }
}
