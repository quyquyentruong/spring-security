package lab_quyentq.spring_security.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.PrivateKey;

public class JwtTokenGenerator
{
    public static String generateToken(PrivateKey privateKey) {
        // Tạo JWT mà không có payload và thời gian hết hạn
        return Jwts.builder()
                .signWith(privateKey, SignatureAlgorithm.RS256) // Ký bằng RSA SHA256
                .compact();
    }
}
