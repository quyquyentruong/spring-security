package lab_quyentq.spring_security.services.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

public class GenerateKeyPair {
    public static List<HashMap<String, String>> createKeyPair() throws Exception {
        // Tạo KeyPairGenerator cho RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024); // Độ dài của khóa

        // Tạo cặp khóa RSA
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Xuất khóa thành chuỗi Base64
        String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        HashMap<String, String> publicKeyPair = new HashMap<>();
        publicKeyPair.put("Public-Key", publicKeyStr);

        HashMap<String, String> privateKeyPair = new HashMap<>();
        privateKeyPair.put("Private-Key", privateKeyStr);

        List<HashMap<String, String>> keyPairList = new ArrayList<>();
        keyPairList.add(publicKeyPair);
        keyPairList.add(privateKeyPair);

        return keyPairList;
    }
}
