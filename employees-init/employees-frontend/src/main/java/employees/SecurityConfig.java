package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(registry -> registry
                                .requestMatchers( "/create-employee")
//                                .authenticated()
                                .hasRole("employees_write")
//                                .requestMatchers( "/")
//                                .hasRole("employees_read")
                                .anyRequest()
                                .permitAll()
                )
                .oauth2Login(Customizer.withDefaults())
                .logout(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> authorities.stream().flatMap(authority -> {
            if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                var realmAccess = (Map<String, Object>) oidcUserAuthority.getAttributes().get("realm_access");
                var roles = (List<String>)realmAccess.get("roles");


//                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
//                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                // Map the claims found in idToken and/or userInfo
                // to one or more GrantedAuthority's and add it to mappedAuthorities
                return roles.stream()
                        .map(roleName -> "ROLE_" + roleName)
                        .map(SimpleGrantedAuthority::new);


            } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                // Map the attributes found in userAttributes
                // to one or more GrantedAuthority's and add it to mappedAuthorities
                return Stream.of();
            }
            else if (authority instanceof SimpleGrantedAuthority simpleGrantedAuthority) {
                return Stream.of(simpleGrantedAuthority);
            }
            else {
                throw new IllegalStateException("Invalid authority: %s".formatted(authority.getClass().getName()));
            }
        }).toList();
    }
}
