package spring.security.global.redis;

public interface TokenRepository {

    void addRefreshToken(String key, String value);
    String getRefreshToken(String key);
    boolean deleteRefreshToken(String key);
    void addBlackListAccessToken(String token);
    boolean existBlackListAccessToken(String token);
}
