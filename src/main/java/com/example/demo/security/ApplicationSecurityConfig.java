package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtSecretKey;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
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
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final ApplicationUserService applicationUserService;
    private final PasswordEncoder passwordEncoder;
    private final JwtConfig jwtConfig;
    private final JwtSecretKey jwtSecretKey;
    @Autowired
    public ApplicationSecurityConfig(ApplicationUserService applicationUserService,
                                     PasswordEncoder passwordEncoder,
                                     JwtConfig jwtConfig,
                                     JwtSecretKey jwtSecretKey) {
        this.applicationUserService = applicationUserService;
        this.passwordEncoder = passwordEncoder;
        this.jwtConfig = jwtConfig;
        this.jwtSecretKey = jwtSecretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http
                   // .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Configure the csrf
                   // .and()
                    .csrf().disable()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Since the JWT is stateless
                    .and()
                    .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig , jwtSecretKey)) // To enable JWT authentication
                    .addFilterAfter(new JwtTokenVerifier(jwtConfig , jwtSecretKey), JwtUsernameAndPasswordAuthenticationFilter.class) // To verify the JWT
                    .authorizeRequests()
                    .antMatchers("/", "index", "/css/*" , "/js/*")
                    .permitAll()
                    .antMatchers("/api/**").hasRole(STUDENT.name())
//                    .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                    .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                    .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                    .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                    .anyRequest()
                    .authenticated(); // User must provide username and password




    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails annaSmithUser = getUser("annasmith" , "password" , STUDENT);
//        UserDetails lindaUser = getUser("linda" , "password123" , ADMIN);
//        UserDetails tomUser = getUser("tom" , "password123" , ADMINTRAINEE);
//        return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    private UserDetails getUser(String name, String password, ApplicationUserRole role) {
//        return User.builder()
//                .username(name)
//                .password(passwordEncoder.encode(password))
//                //.roles(role.name()) // ROLE_STUDENT
//                .authorities(role.getGrantedAuthorities())
//                .build();
//    }


    /*
    .httpBasic();
    .formLogin().
    loginPage("/login").permitAll() // This will return a custom login page on the path = /login
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password") // you can customize the name parameter in the HTML form
                    .usernameParameter("username")
                    .and()
                    .rememberMe() // defaults to 2 weeks.
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
            .key("somethingverysecured")
                    .rememberMeParameter("remember-me")
                    .and()
                    .logout().logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // If csrf is enabled you should remove this line
            .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID" , "remember-me")
                    .logoutSuccessUrl("/login"); */
}
