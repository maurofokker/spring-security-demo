package com.maurofokker.demo.spring;

import com.maurofokker.demo.model.SecurityQuestion;
import com.maurofokker.demo.model.SecurityQuestionDefinition;
import com.maurofokker.demo.model.User;
import com.maurofokker.demo.persistence.SecurityQuestionRepository;
import com.maurofokker.demo.persistence.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@ComponentScan({ "com.maurofokker.demo.security" })
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SecurityQuestionRepository securityQuestionRepository;

    public BasicSecurityConfig() {
        super();
    }

    //


    @PostConstruct
    private void saveTestUser() {
        final User user = new User();
        user.setEmail("test@mail.com");
        // user.setPassword(passwordEncoder().encodePassword("password", null)); // md5 deprecated password encoder
        user.setPassword(passwordEncoder().encode("password")); // stardard encoder sha-256
        userRepository.save(user);
        final SecurityQuestionDefinition questionDefinition = new SecurityQuestionDefinition();
        questionDefinition.setId(6L);
        questionDefinition.setText("Who was your childhood hero?");
        securityQuestionRepository.save(new SecurityQuestion(user, questionDefinition, "Hulk"));
    }


    /**
     * wire userDetailsService into authentication config
     * remove in memory
     * this allow to register and then authenticate the new user
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { // @formatter:off
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    } // @formatter:on

    /**
     * Difference btw use of Role and Authority in url authorization:
     *  hasRole("ADMIN") looks for `ROLE_` prefix authority (so it really checks for `ROLE_ADMIN` authority)
     *  hasAuthority("ADMIN") looks for ADMIN, so `Authority` API don't looks for prefix, is new and clean
     * Url authorization goes from specific (delete) to general (anyReq)
     * Default login form page is /login also the processing url page is /login
     * the reason for not wanting to use the default is that the defaults basically leak implementation details
     * Logout url default is /logout so it needs to change
     *  logoutRequestMatcher(...) allow to be stricter and specify exact http method to do logout
     *  if CSRF is enabled, GET won’t work for logging out, only POST
     *  we should only use POST anyways, since logout is an operation that changes the state of the system
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/signup"
                            , "/user/register"
                            , "/registrationConfirm*"
                            , "badUser*"
                            , "/forgotPassword*"
                            , "/user/resetPassword*"
                            , "/user/changePassword*"
                            , "/user/savePassword*"
                            , "/js/**"
                        ).permitAll() // give access to url and operation
                    .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
                    .loginProcessingUrl("/doLogin") // login proccesion url where authentication happens
                .and()
                .logout()
                    .permitAll().logoutUrl("/logout")

                .and()
                .rememberMe()
                    .key("demosecapp")
                    .tokenValiditySeconds(604800) // 1 week = 604800
                    .tokenRepository(persistentTokenRepository())
                    .rememberMeParameter("remember")

                .and()
                .csrf().disable()
        ;
    }

    /**
     * using the JdbcTokenRepositoryImpl of PersistentTokenRepository
     * PersistentTokenRepository has 2 implementatios, this one and InMemoryTokenRespositoryImpl (default)
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        final JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource); // to connect to db
        return  jdbcTokenRepository;
    }

    /**
     * Implement password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        //return new Md5PasswordEncoder(); // deprecated MD% password encoder implementation
        return new StandardPasswordEncoder(); // this is the standard enconder sha-256
    }
}
