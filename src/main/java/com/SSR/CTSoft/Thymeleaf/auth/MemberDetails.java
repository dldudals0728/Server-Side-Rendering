package com.SSR.CTSoft.Thymeleaf.auth;

import com.SSR.CTSoft.Thymeleaf.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Data
public class MemberDetails implements UserDetails {
    private final User user;    // 컴포지션

    public MemberDetails(User user) {
        this.user = user;
    }   // 생성자 생성

    // 해당 User의 권한을 return
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 현재 권한은 User.role 이다. 하지만 String type을 return 할 수 없기 때문에 권한을 만들어준다.
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new SimpleGrantedAuthority(this.user.getRole()));
//        collection.add(new GrantedAuthority() {
//            @Override
//            public String getAuthority() {
//                return user.getRole();
//            }
//        });
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }   // 계정 만료

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }   // 계정 잠김

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }   // 비밀번호 변경한지 1년 이상

    @Override
    public boolean isEnabled() {
        System.out.println("is Enabled function");
        System.out.println(this.getUsername());
        System.out.println(this.getPassword());
        return true;
    }
}
