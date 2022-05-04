package com.example.demo.spring.security.config;

import com.example.demo.spring.security.jwt.JwtConfig;
import com.example.demo.spring.security.jwt.JwtTokenVerifier;
import com.example.demo.spring.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.example.demo.spring.security.service.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.spring.security.config.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                              ApplicationUserService applicationUserService,
                              JwtConfig jwtConfig,
                              SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /**
                 * Disabling CSRF
                 */
                //.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .csrf().disable()
                /**
                 * Doing this for JWT configuration
                 * 1.  Setting session management stateless policy
                 */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                /**
                 * Above part is about sending the JWS to the requester
                 * Now we verify the JWT and authenticate the context
                 */
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                /**
                 * JWT ======= END
                 */
                .authorizeRequests()
                .antMatchers("/", "/test", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                /**
                 * Since code is using actual @PreAuthorise annotitaion so following lines are not
                 * required.
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                */
                .anyRequest()
                .authenticated()
                /**
                 * Disabling Basic authentication
                 * moving to form base authentication.
                 */
                //.httpBasic()
                /**
                 * Now moving from formbase auth to JWT Auth.
                 * So blocking comitting below part..
                 */
                /*
                .and()
                .formLogin()// Now form base login is enabled
                    .loginPage("/login").permitAll() // setting custom login path and allowing all to access login page
                    .defaultSuccessUrl("/courses", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                .and()
                .rememberMe() // default is for two weeks
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher( new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login")
                 */
                 ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

/*    @Autowired
    public void configureGlobal(final UserDetailsService userDetailsService,
                                final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }*/


    /**
     *
     * The following userDetailsService is not required
     * as now we have implemented our own Authentication Provider.
     * So commingting this part.
     */
    /*
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        UserDetails annasmith = User.builder()
                .username("annasmith")
                .passwordEncoder(passwordEncoder :: encode)
                .password("password")
                //.roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails linda = User.builder()
                .username("linda")
                .passwordEncoder(passwordEncoder :: encode)
                .password("password")
                //.roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tom = User.builder()
                .username("tom")
                .passwordEncoder(passwordEncoder :: encode)
                .password("password")
                //.roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(annasmith, linda, tom);
    }
     */
}
