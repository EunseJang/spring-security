package spring.security.global.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import spring.security.user.domain.UserType;

import java.util.ArrayList;
import java.util.List;

public class GrandUtils {

    /** Spring Security에서 사용되는 권한 생성 */

    public static List<GrantedAuthority> getAuthoritiesByUserType(UserType userType) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // 모든 사용자에게 기본으로 USER 권한 부여
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        // 관리자인 경우 ADMIN 권한 부여
        if (userType.equals(UserType.ADMIN)) {
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        return grantedAuthorities;
    }
}
