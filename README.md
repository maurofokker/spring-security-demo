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

## Add persistence configuration
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
import com.maurofokker.demo.model.User;
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

### Active account via Email
* Activate registration using a verification token
```java
@Entity
public class VerificationToken {

    private static final int EXPIRATION = 60 * 24;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    private Date expiryDate;
    
    // getters and setters
}
```
* Persistence API for verification token
```java
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);
}
```
* User is `disabled` by default when created
* When created user is loaded and wired it with spring security user details service, account status (`enable`) is get from the user entity
```java
@Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        final User user  = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), user.getEnabled(), true, true, true, getAuthorities("ROLE_USER"));
    }
```
* During registration controller is sent an event to notify the newly created user (`RegistrationContoller.registerUser`)
* Event is received by a listener that will send a verification email to new user to confirm registration (`RegistrationListener`)
    * Token is created
    * Email is sent
* Confirm registration is received by `/registrationConfirm` API (`RegistrationController.confirmRegistration`)
    * User is retrieved using token (loaded from db)
    * Do some validations related to token dates
    * Set user enabled in db
    * Redirect to login page

### Forgot/Reset Password
#### Forgot password
* Add link to forgot password page
* Add form to trigger reset password by email to `/user/resetPassword` API
* Add view controller to accesss to `forgotPassword`
```java
registry.addViewController("/forgotPassword").setViewName("forgotPassword");
```
* Add urls `/forgotPassword` and `/user/resetPassword*`  to the allowed list
```java
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
            .csrf().disable()
    ;
}
```
* Implementation of reset password logic
    * Controller receive reset password request
    * Load user by email
    * If user exists, create password reset token for user (this is different token from creation because manage expiration)
    * Token is send to user via Email just like confirmation
    * TODO: this step could be managed by event and listener
```java
@RequestMapping(value = "/user/resetPassword", method = RequestMethod.POST)
@ResponseBody
public ModelAndView resetPassword(final HttpServletRequest request, @RequestParam("email") final String userEmail, final RedirectAttributes redirectAttributes) {
    final User user = userService.findUserByEmail(userEmail);
    if (user != null) {
        final String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        final String appUrl = "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
        final SimpleMailMessage email = constructResetTokenEmail(appUrl, token, user);
        mailSender.send(email);
    }

    redirectAttributes.addFlashAttribute("message", "You should receive an Password Reset Email shortly");
    return new ModelAndView("redirect:/login");
}
```
* Service method for token reset creation
```java
@Override
public void createPasswordResetTokenForUser(final User user, final String token) {
    final PasswordResetToken myToken = new PasswordResetToken(token, user);
    passwordTokenRepository.save(myToken);
}
```
* `PasswordResetToken` entity to control lifetime expiration of token
```java
@Entity
public class PasswordResetToken {

    private static final int EXPIRATION = 60 * 24;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    private Date expiryDate;

    public PasswordResetToken() {
        super();
    }

    public PasswordResetToken(final String token, final User user) {
        super();

        this.token = token;
        this.user = user;
        this.expiryDate = calculateExpiryDate(EXPIRATION);
    }

    // setter and getters

    private Date calculateExpiryDate(final int expiryTimeInMinutes) {
        final Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(new Date().getTime());
        cal.add(Calendar.MINUTE, expiryTimeInMinutes);
        return new Date(cal.getTime().getTime());
    }
}
```
* Persistence repo for PasswordResetToken
```java
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    PasswordResetToken findByToken(String token);
}
```
#### Reset password
* Add controller method to show `reset password` page sent via email using the password reset token
```java
@RequestMapping(value = "/user/changePassword", method = RequestMethod.GET)
public ModelAndView showChangePasswordPage(@RequestParam("id") final long id, @RequestParam("token") final String token, final RedirectAttributes redirectAttributes) {
    final PasswordResetToken passToken = userService.getPasswordResetToken(token);
    if (passToken == null) {
        redirectAttributes.addFlashAttribute("errorMessage", "Invalid password reset token");
        return new ModelAndView("redirect:/login");
    }
    // retrieve user with passToken

    // check if password reset token is expired

    // create nee authentication with UsernamePasswordAuthenticationToken
    final Authentication auth = new UsernamePasswordAuthenticationToken(user, null, userDetailsService.loadUserByUsername(user.getEmail()).getAuthorities());
    // set the principal auth for the context of the next operation where is going to be save in db
    SecurityContextHolder.getContext().setAuthentication(auth);
    
    // return to resetPassword page where user must enter new password
    return new ModelAndView("resetPassword");
}
```
* Add `resetPassword.html` to reset password
* Add controller method triggered when user send new password
```java
@RequestMapping(value = "/user/savePassword", method = RequestMethod.POST)
@ResponseBody
public ModelAndView savePassword(@RequestParam("password") final String password, @RequestParam("passwordConfirmation") final String passwordConfirmation, final RedirectAttributes redirectAttributes) {
    if (!password.equals(passwordConfirmation)) {
        return new ModelAndView("resetPassword", ImmutableMap.of("errorMessage", "Passwords do not match"));
    }
    // principal authentication from security context
    final User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    userService.changeUserPassword(user, password);
    redirectAttributes.addFlashAttribute("message", "Password reset successfully");
    return new ModelAndView("redirect:/login");
}
```
* Add urls `/user/changePassword` and `/user/savePassword`  to the allowed list
```java
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
            .csrf().disable()
    ;
}
```

#### Security questions for registration and reset password validation
1. Define security questions
2. Security questions definition persistence with relation to user
3. Add security questions to registration form
4. Add security question to resgistration controller logic
5. Use security question validation when reset password

* Add entity with security question definitions
```java
@Entity
public class SecurityQuestionDefinition {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    @NotEmpty
    private String text;
    
    // setter getters
}
```
* Add entity with security questions relation with user and definitions
```java
@Entity
public class SecurityQuestion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // relation with User
    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id", unique = true)
    private User user;

    // relation with Security Question Definition
    @OneToOne(targetEntity = SecurityQuestionDefinition.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "securityQuestionDefinition_id")
    private SecurityQuestionDefinition questionDefinition;

    private String answer;

    public SecurityQuestion(final User user, final SecurityQuestionDefinition questionDefinition, final String answer) {
        this.user = user;
        this.questionDefinition = questionDefinition;
        this.answer = answer;
    }
    
    // setter getters
}
```

* Repositories persistence for `SecurityQuestionDefinition` and `SecurityQuestion`
```java
public interface SecurityQuestionDefinitionRepository extends JpaRepository<SecurityQuestionDefinition, Long> {
}
```
```java
public interface SecurityQuestionRepository extends JpaRepository<SecurityQuestion, Long> {
    // retrieve security question by question definition, user id and answer
    SecurityQuestion findByQuestionDefinitionIdAndUserIdAndAnswer(Long questionDefinitionId, Long userId, String answer);
}
```

* Registration logic with questions
```java
@RequestMapping(value = "signup")
public ModelAndView registrationForm() {
    Map<String, Object> model = new HashMap<>();
    model.put("user", new User());
    model.put("questions", securityQuestionDefinitionRepository.findAll());
    return new ModelAndView("registrationPage", model);
}
```
* Front will display questions
```html
<div class="form-group">
    <label class="control-label col-xs-2" for="question">Security Question:</label>
    <div class="col-xs-10">
        <select id="question" name="questionId">
            <option th:each="question : ${questions}"
                    th:value="${question.id}"
                    th:text="${question.text}">Question</option>
        </select>
    </div>
</div>
<div class="form-group">
    <label class="control-label col-xs-2" for="answer">Answer</label>
    <div class="col-xs-10">
        <input id="answer" type="text" name="answer"/>
    </div>
</div>
```
* After persist user we need to persist question related to user. This should be in a single transaction (user creation and question persistence)
```java
final SecurityQuestionDefinition questionDefinition = securityQuestionDefinitionRepository.findOne(questionId);
securityQuestionRepository.save(new SecurityQuestion(user, questionDefinition, answer));
```
* Secure password reset with security question related
```java
if (securityQuestionRepository.findByQuestionDefinitionIdAndUserIdAndAnswer(questionId, user.getId(), answer) == null) {
    final Map<String, Object> model = new HashMap<>();
    model.put("errorMessage", "Answer to security question is incorrect");
    model.put("questions", securityQuestionDefinitionRepository.findAll());
    return new ModelAndView("resetPassword", model);
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