package com.maurofokker.demo.spring;

import com.google.common.collect.Lists;
import com.maurofokker.demo.model.Role;
import com.maurofokker.demo.model.SecurityQuestion;
import com.maurofokker.demo.model.SecurityQuestionDefinition;
import com.maurofokker.demo.model.User;
import com.maurofokker.demo.persistence.RoleRepository;
import com.maurofokker.demo.persistence.SecurityQuestionRepository;
import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.security.filter.LoggingFilter;
import com.maurofokker.demo.security.voters.RealTimeLockVoter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.RunAsImplAuthenticationProvider;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
@ComponentScan({ "com.maurofokker.demo.security" })
@EnableAsync
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityQuestionRepository securityQuestionRepository;

    @Autowired
    private LoggingFilter loggingFilter;

    @Autowired
    private RoleRepository roleRepository;

    //@Autowired
    //private CustomAuthenticationProvider customAuthenticationProvider;

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
        // user.setPassword("password");
        final Role role = roleRepository.findByName("ROLE_ADMIN");
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        user.setRoles(roles);
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
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
         //auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()); // this contains by default DaoAuthenticationProvider

        // auth.authenticationProvider(customAuthenticationProvider); // should implement encoder and salt but is for simple login

        auth.authenticationProvider(daoAuthenticationProvider());
        auth.authenticationProvider(runAsAuthenticationProvider());
    }

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
                .addFilterBefore(loggingFilter, AnonymousAuthenticationFilter.class) // add custom LoggingFilter in chain before of AnonymousAuthenticationFilter
                .authorizeRequests()
                    .antMatchers("/secured").access("hasRole('ADMIN')") // for web expression voter
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
                                .accessDecisionManager(unnanimous()) // use bean with unnanimous decision manager that add custom voter
                .and()
                .formLogin()
                    .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
                    .loginProcessingUrl("/doLogin") // login proccesion url where authentication happens
                .and()
                .logout()
                    .permitAll().logoutUrl("/logout")

                .and()
                .sessionManagement()
                    .maximumSessions(1)
                    .sessionRegistry(sessionRegistry()) // register this session registry into our security configuration
                    .and()
                    .sessionFixation().none() // this is need to close the session configuration

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

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
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
        //return new StandardPasswordEncoder(); // this is the standard enconder sha-256
        return new BCryptPasswordEncoder(12); // implements bcrypt encoder
    }

    @Bean
    public AuthenticationProvider runAsAuthenticationProvider() {
        final RunAsImplAuthenticationProvider authProvider = new RunAsImplAuthenticationProvider();
        authProvider.setKey("MyRunAsKey"); // same as DemoMethodSecurityConfig.runAsManager method
        return authProvider;
    }
    @Bean
    public AuthenticationProvider daoAuthenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }


    /**
     * This is done in a new class and not in BasicSecurityConfig.java, because the latter already
     * extends a base class (WebSecurityConfigurerAdapter)
     */
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

        @Override
        public MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
            final Map<String, List<ConfigAttribute>> methodMap = new HashMap<>(); // map with methods to secure
            methodMap.put("com.maurofokker.demo.web.controller.UserController.createForm*", SecurityConfig.createList("ROLE_ADMIN"));
            return new MapBasedMethodSecurityMetadataSource(methodMap);
        }

    }

    /**
     * Implements Unnanimous voter adding a custom RealTimeLockVoter
     * @return
     */
    @Bean
    public AccessDecisionManager unnanimous(){
        final List<AccessDecisionVoter<? extends Object>> voters = Lists.newArrayList(new RoleVoter(), new AuthenticatedVoter(), new RealTimeLockVoter(), new WebExpressionVoter());
        return new UnanimousBased(voters);
    }

}
