package spring.security.global.config;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RedissonConfig {

    @Value("${spring.data.redis.host}")
    private String host;

    @Value("${spring.data.redis.port}")
    private int port;

    private static final String REDISSON_HOST_PREFIX = "redis://";

    // Redisson 클라이언트 빈들 생성하는 메서드
    @Bean
    public RedissonClient redissonClient() {
        RedissonClient redisson;
        Config config = new Config();

        // Redis 서버의 연결 정보 설정
        config.useSingleServer().setAddress(REDISSON_HOST_PREFIX + host + ":" + port);
        redisson = Redisson.create(config);

        return redisson;
    }
}
