# Spring Security

## Configuration

### Dependency
#### Spring boot
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```
#### Without spring boot
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>${spring-security.version}</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>${spring-security.version}</version>
</dependency>
```

### Change defaults from application.properties in spring boot
``` 
security.user.name=user
security.user.password=password
security.basic.authorize-mode=authenticated
security.basic.path=/**
```
* above enable basic authentication

### Basic java configuration
```java
@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("user").password("password")
            .roles("USER_ADMIN")
            ;
    }
}
```
* change the global configuration
* disable basic auth config
* replace basic auth with default login form config (auto generated in this case bc default configure method in WebSecurityConfigurerAdapter)
* is possible to override auto generated form

### Url authorization

* Override method `configure` from `WebSecurityConfigurerAdapter`
* Difference btw use of Role and Authority in url authorization:
    *  hasRole("ADMIN") looks for `ROLE_` prefix authority (so it really checks for `ROLE_ADMIN` authority)
    *  hasAuthority("ADMIN") looks for ADMIN, so `Authority` API don't looks for prefix, is new and clean
* Url authorization goes from specific (delete) to general (anyRequest)
* If a user that try to access an URL secured and don't have authority then a 403 status code is send by API
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .antMatchers("/delete/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        .and()
        .formLogin()    // this is default login created by spring when no overriding configure method
    ;
}
```
#### Some types of authorizations
* hasAuthority: is the principal authority
* hasAnyRole: can have any role configured (ROLE_ADMIN, ROLE_ROOT)
* hasAnyAuthority: can have any of authorities passed (ADMIN, ROOT)
* hasIpAddress: not very used in production, useful to be able to pinpoint a specific ip address
* access: allow the use of expressions
* authenticated: just need to be authenticated in order to use url, no special authority or privilege just authenticated
* anonymous: any type of access is ok for url
* denyAll: restrict any kind of access
* permitAll
* fullyAuthenticated, rememberMe: are tied 
* not: allow chaining 

### Custom login form page config
* Configured in method `configure` (overrid) of `WebSecurityConfigurerAdapter`
* Default login form page is /login also the processing url page is /login
* Reason for not wanting to use the default configuration is that the defaults basically leak implementation details
* When using defaults other people can know about the framework and can exploit vulnerabilities if not patched
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
       .authorizeRequests()
           //.antMatchers("/delete/**").hasRole("ADMIN")
           .anyRequest().authenticated()
       .and()
       .formLogin()    
           .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
           .loginProcessingUrl("/doLogin") // login proccesion url where authentication happens
       .and()
       .csrf().disable()
    ;
}
```
* Create login page (thymeleaf) and reference it with a controller
```java
@RequestMapping("/login")
public String list() {
    return "loginPage";
}
```
## References

1 [Java Configuration in Spring Security](http://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#jc)

2 [Authorization Architecture](https://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#authorization)

3 [Java Config and Form Login in the Spring Security](http://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-form)