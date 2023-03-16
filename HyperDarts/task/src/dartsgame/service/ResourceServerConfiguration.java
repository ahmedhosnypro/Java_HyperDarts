package dartsgame.service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    String publicKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQ+7yKlJGuvYtf1soMsJjkQJGAXe90QAxqppycf+3JT5ehnvvWtwS8ef+UsqrNa5Rc9tyyHjP7ZXRN145SlRTZzc0d03Ez10OfAEVdhGACgRxS5s+GZVtdJuVcje3Luq3VIvZ8mV/P4eRcV3yVKDwQEenMuL6Mh6JLH48KxgbNRQIDAQAB-----END PUBLIC KEY-----";

    private TokenStore tokenStore;

    // Create JwtTokenStore with this token enhancer
    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    // Add resource-server specific properties (the resource id from previous stage).
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("api");
    }

    // Use the following to configure access rules for secure resources.
    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/actuator/shutdown").permitAll() // needs to run test
                .antMatchers(HttpMethod.GET, "/**")
                .access("(#oauth2.hasScope('read') and hasRole('ROLE_GAMER'))")
                .antMatchers(HttpMethod.POST, "/**")
                .access("(#oauth2.hasScope('write') and hasRole('ROLE_GAMER'))")
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable();
    }

    // A helper that exchanges JWT encoded token values and OAuth authentication
    // information (both directions). It also acts as a TokenEnhancer when the tokens are granted.
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setVerifierKey(publicKey);
        return converter;
    }

}