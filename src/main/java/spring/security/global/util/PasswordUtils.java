package spring.security.global.util;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordUtils {

    // 평문 비밀번호 비교
    public static boolean equalsPlainText(String pw1, String pw2) {
        return pw1.equals(pw2);
    }

    // 평문 비밀번호 vs 해시 비밀번호
    public static boolean equalsPlainTextAndHashed(String plainText, String hashed) {
        if(plainText == null || plainText.isEmpty()) {
            return false;
        }

        if (hashed == null || hashed.isEmpty()) {
            return false;
        }

        return BCrypt.checkpw(plainText, hashed);
    }

    // 평문 비밀번호를 해싱 알고리즘 처리
    public static String encPassword(String plainText) {
        if(plainText == null || plainText.isEmpty()) {
            return "";
        }

        return BCrypt.hashpw(plainText, BCrypt.gensalt());
    }
}
