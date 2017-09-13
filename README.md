# Spring Security Demo

## Technology
* Java 8+
* Spring Boot 1.5.4
* Spring data jpa for persistence
* Maven 3.0+

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
* `hasAuthority`: is the principal authority
* `hasAnyRole`: can have any role configured (ROLE_ADMIN, ROLE_ROOT)
* `hasAnyAuthority`: can have any of authorities passed (ADMIN, ROOT)
* `hasIpAddress`: not very used in production, useful to be able to pinpoint a specific ip address
* `access`: allow the use of expressions
* `authenticated`: just need to be authenticated in order to use url, no special authority or privilege just authenticated
* `anonymous`: any type of access is ok for url
* `denyAll`: restrict any kind of access
* `permitAll`
* `fullyAuthenticated`, rememberMe: are tied 
* `not`: allow chaining 

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

### Logout configuration
* Logout url default is /logout so it needs to change
* `.logout().logoutRequestMatcher(new AntPathRequestMatcher("/doLogout", "GET"))` allow to be stricter and specify exact http method to do logout
* if CSRF is enabled, GET won’t work for logging out, only POST
* only POST must be used, since logout is an operation that changes the state of the system

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
  http
      .authorizeRequests()
          .anyRequest().authenticated()
      .and()
      .formLogin()
          .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
          .loginProcessingUrl("/doLogin") // login proccesing url where authentication happens
      .and()
      .logout()
          .permitAll().logoutUrl("/logout") // logout processing page
              //.clearAuthentication()
              //.deleteCookies()
              //.invalidateHttpSession()
              //.logoutSuccessHandler()
              //.logoutSuccessUrl()
      .and()
      .csrf().disable()
  ;
}
```

#### Other config that wraps logout
* `clearAuthentication`: is true by default, but can be turn it off. Typically, that's not something wanted, but there are production scenarios where you might need to make sure that you don't clear authentication when your user logs out
* `deleteCookies`: nice way to specify that when your user logs out, a list of custom cookies should be cleared. When using custom cookies that do need to be cleared on logout, this is the way to do it
* `invalidateHttpSession`: enabled by default, it's something that you can change if you have a scenario that requires you to not invalidate the session when your user logs out
* `logoutSuccessUrl`: when logged out, we were automatically redirected to the login page, with an extra logout parameter. You may want to have a custom logout page saying you have been logged out, and maybe presenting some extra information. So if you need the logout process to redirect to a different page, not the login page, this is the way to do it
* `logoutSuccessHandler`: to run extra logic when logged out. this is basically a way to hook into the logout process and run some custom logic. So for example, when you have other external systems that need to be aware when you're logging out

## Anonymous Authentication
* Helper, artificial, concept in spring that is helpful in some scenarios
* There are scenarios where if no principal is currently logged in, then a lot of extra code is needed (write) and a lot of extra logic to work around that problem
    * `Scenario 1 Login`: common login config is including the username in the log message, in order to debug or trace activities by username. When that logging logic 
    runs within a non-secured context (this login page) that logic will have to deal with a `null` principal. Unless exists a `default` anonymous principal to put in
    the log message, the system is goint to have to deal with that null. So that anonymous authentication just helps in that scenario.
    * `Scenario 2 Auditing`: in most systems, audit logs will have a user, the problem is that when generating an audit entry from a non­secured part of the application, 
    we run into the same problem where don't have user to use in the audit entry. That is why this anonymous authentication or anonymous user can help. And again, 
    once you're authenticated in the application, the real principal will be available in the Spring Security context, so this is just for those areas of the application, 
    where you are not yet authenticated.
* Anonymous authentication token is going to be available whenever a real principal, an authenticated principal, is not available
    * For example, if the audit code is using the principal out of the Spring Security authentication, there is no need to write special code, and there is no need to do null checking or any other checks on the authentication, and everything is going to be working out of the box

## Registration flow with spring security

### Simple registration form
* Controller method to display registration form
```java
@RequestMapping(value = "signup")
public ModelAndView registrationForm() {
    return new ModelAndView("registrationPage", "user", new User());
}
```
* Thymeleaf registration page
* Controller method to registration logic from registration form action
```java
@RequestMapping(value = "user/register")
public ModelAndView registerUser(@Valid User user, BindingResult result) {
    if (result.hasErrors()) {
        return new ModelAndView("registrationPage", "user", user);
    }
    try {
        userService.registerNewUser(user);
    } catch (EmailExistsException e) {
        result.addError(new FieldError("user", "email", e.getMessage()));
        return new ModelAndView("registrationPage", "user", user);
    }
    return new ModelAndView("redirect:/login");
}
```
* Service method to implement registration of new user logic
```java
@Override
public User registerNewUser(final User user) throws EmailExistsException {
    if (emailExist(user.getEmail())) {
        throw new EmailExistsException("There is an account with that email address: " + user.getEmail());
    }
    return repository.save(user);
}

private boolean emailExist(String email) {
    final User user = repository.findByEmail(email);
    return user != null;
}
```
* Security config to allow access to registration form
```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/signup", "/user/register").permitAll() // give access to url and operation
                    .anyRequest().authenticated()
                .and()
                .formLogin()
                    .loginPage("/login").permitAll() // login form page, exception to be available for people not logged in
                    .loginProcessingUrl("/doLogin") // login proccesion url where authentication happens
                .and()
                .logout()
                    .permitAll().logoutUrl("/logout")
                .and()
                .csrf().disable()
        ;
    }
```

### Register and authenticate real users
* Authentication with newly registered users that were persisted in db
* Implementation of spring security UserDetailsService interface
```java
@Transactional
@Service
public class DemoUserDetailsService implements UserDetailsService {

    // needed bc there are gonna be persistence work
    // to retrieve user
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        final User user  = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, getAuthorities("ROLE_USER"));
    }

    /**
     * wrapping authorities in the format spring security expects
     * add authority in collection
     * @param role
     * @return
     */
    private Collection<? extends GrantedAuthority> getAuthorities(String role) {
        return Arrays.asList(new SimpleGrantedAuthority(role));
    }
}
```
* Wire UserDetailsService in security configuration
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
} 
```


## Persistence configuration
* Dependency for spring data and spring boot is easy
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```
* For development and test is good to use in memory data bases like hsql
```xml
<dependency>
	<groupId>org.hsqldb</groupId>
	<artifactId>hsqldb</artifactId>
	<scope>runtime</scope>
</dependency>
<!-- <dependency> -->
<!-- <groupId>mysql</groupId> -->
<!-- <artifactId>mysql-connector-java</artifactId> -->
<!-- <version>${mysql.version}</version> -->
<!-- </dependency> -->
```

* Configuration is done with java annotations 
```java
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(basePackages = "com.maurofokker.demo.persistence")
@EntityScan("com.maurofokker.demo.web.model")
public class DemoPersistenceJpaConfig {
}
```
* Entities are annotated 
```java
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.Calendar;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty(message = "Username is required.")
    private String username;

    @NotEmpty(message = "Email is required.")
    private String email;

    private Calendar created = Calendar.getInstance();

    // getters and setters
}
```
* For crud operations spring data comes with handy functions out of the box
```java
import com.maurofokker.demo.web.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
```
* `JpaRepository` and `MongoRepository` interfaces extend `CrudRepository` It takes the domain class to manage as well as the id type of the domain class as type arguments
  The `CrudRepository` provides sophisticated CRUD functionality for the entity class that is being managed

* `CrudRepository` interface
```java
public interface CrudRepository<T, ID extends Serializable>
    extends Repository<T, ID> {

    <S extends T> S save(S entity); 

    T findOne(ID primaryKey);       

    Iterable<T> findAll();          

    Long count();                   

    void delete(T entity);          

    boolean exists(ID primaryKey);  

    // … more functionality omitted.
}
```
## Troubleshootings

[Thymeleaf and @EnableWebMvc](https://stackoverflow.com/questions/29562471/springboot-with-thymeleaf-css-not-found)

## References

### Spring Security

1 [Java Configuration in Spring Security](http://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#jc)

2 [Authorization Architecture](https://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#authorization)

3 [Java Config and Form Login in the Spring Security](http://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-form)

4 [Logout in the Spring Security Reference](http://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-logout)

5 [Anonymous Authentication in the Spring Security Reference](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#anonymous)

6 [Registration form](http://www.baeldung.com/spring-security-registration)
### Persistence

1 [Spring Data Jpa](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/)

2 [Introduction to jpa with spring boot data jpa](http://www.springboottutorial.com/introduction-to-jpa-with-spring-boot-data-jpa)