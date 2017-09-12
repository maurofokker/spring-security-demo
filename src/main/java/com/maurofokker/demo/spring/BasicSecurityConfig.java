package com.maurofokker.demo.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

    //

    /**
     * change the global configuration
     * - disable basic auth config
     * - replace basic auth with default login form config (auto generated in this case)
     * - is possible to override auto generated form
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { // @formatter:off
        auth.
                inMemoryAuthentication().
                withUser("user").password("password").
                roles("USER");
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
                    .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
                    .loginProcessingUrl("/doLogin") // login proccesion url where authentication happens
                .and()
                .logout()
                    .permitAll().logoutUrl("/logout")
                    //.logoutRequestMatcher(new AntPathRequestMatcher("/doLogout", "GET"))
                        //.clearAuthentication()
                        //.deleteCookies()
                        //.invalidateHttpSession()
                        //.logoutSuccessHandler()
                        //.logoutSuccessUrl()
                .and()
                .csrf().disable()
        ;
    }
}
