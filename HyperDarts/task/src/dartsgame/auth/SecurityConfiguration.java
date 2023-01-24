package dartsgame.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Hardcoded users, passwords and roles
        auth.inMemoryAuthentication()
                .withUser("ivanhoe@acme.com")
                .password("{noop}oMoa3VvqnLxW")
                .roles("GAMER")
                .and()
                .withUser("robinhood@acme.com")
                .password("{noop}ai0y9bMvyF6G")
                .roles("GAMER")
                .and()
                .withUser("wilhelmtell@acme.com")
                .password("{noop}bv0y9bMvyF7E")
                .roles("GAMER")
                .and()
                .withUser("admin@acme.com")
                .password("{noop}zy0y3bMvyA6T")
                .roles("ADMIN");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}