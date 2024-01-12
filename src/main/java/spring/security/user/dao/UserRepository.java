package spring.security.user.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.user.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}
