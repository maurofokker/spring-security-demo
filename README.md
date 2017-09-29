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

### Password strength for registration
* Should be done in both, frontend and backend
* Should give immediate feedback to user about strength of the password
#### Secure strength password in Frontend
* This will help the user to know if psw is secure in real time with feddback and save the hit to the backend for validation
* Ensure resolution mechanism for static resources are able
```java
@Override
public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/**").addResourceLocations(new String[] { "classpath:/static/" });
}
```
* Use the jquery (in this case) plugin  _jQuery Password Strength Meter for Twitter Bootstrap_ 
```html
<script src="/js/jquery-1.7.2.js"></script>
<script src="/js/pwstrength.js"></script>
```
* Use of jquery plugin to attach password strength mechanism to password field in form
```js
<script type="text/javascript">
    $(document).ready(function () {
        options = {
            common: {minChar:8},
            ui: {
                showVerdictsInsideProgressBar:true,
                showErrors:true,
                errorMessages:{
                    wordLength: 'Your password is too short',
                }
            }
        };
        $('#password').pwstrength(options);
    });
</script>
```
* rule defined for psw strength is `common: {minChar:8}` there are more options

#### Secure strength password in Backend
* It is good to verify password strength rules in the backend too
* Dependency for password validation library
```xml
<!-- Password Validation -->
<dependency>
    <groupId>org.passay</groupId>
    <artifactId>passay</artifactId>
    <version>1.0</version>
</dependency>
```
* Good way is define a custom validator for the password and add logic in that validator. And this is going to be annotated in password field of entity
```java
/**
 * This is the annotation (will go on password field of entity)
 */
@Documented
@Constraint(validatedBy = PasswordConstraintValidator.class)
@Target({ TYPE, FIELD, ANNOTATION_TYPE })
@Retention(RUNTIME)
public @interface ValidPassword {

    String message() default "Invalid Password";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
```

```java
/**
* This is the logic of validation using passay (logic of annotation)
*/
public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public void initialize(final ValidPassword arg0) {
    }

    @Override
    public boolean isValid(final String password, final ConstraintValidatorContext context) {
        // length rule btw 8 and 30 chars, ...
        final PasswordValidator validator = new PasswordValidator(Arrays.asList(new LengthRule(8, 30), new UppercaseCharacterRule(1), new DigitCharacterRule(1), new SpecialCharacterRule(1), new WhitespaceRule()));
        final RuleResult result = validator.validate(new PasswordData(password));
        if (result.isValid()) {
            return true;
        }
        // if validation is false add information to validation context, so frontend can displey that
        context.disableDefaultConstraintViolation();
        // API to add custom message that represents a constraint violation... that information is in the result
        context.buildConstraintViolationWithTemplate(Joiner.on("\n").join(validator.getMessages(result))).addConstraintViolation();
        return false;
    }

}
```
* Use annotation to validate password on user entity
```java
@Entity
@PasswordMatches
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @NotEmpty(message = "Username is required.")
    private String email;

    // use annotation to validate password
    @ValidPassword
    @NotEmpty(message = "Password is required.")
    private String password;

    @Transient
    @NotEmpty(message = "Password confirmation is required.")
    private String passwordConfirmation;

    @Column
    private Boolean enabled;

    private Calendar created = Calendar.getInstance();
    
    // setters getters
}
```
## Remember me flow with spring security
* Logical flow
1. User request use `RememberMeAuthenticationFilter`
2. if `check cookie` is ok then go to next step `decode cookie` else go to next filter
3. if `decode cookie` is ok then go to next step `validate cookie` else throw exception
4. if `validate cookie` is ok then go to next step `check user account` else throw exception
5. if `check user account` is ok then `create authentication token` and go to next filter

### Basic configuration
* Backend configuration in `configure(HttpSecurity http)` method
```java
.and().rememberMe()
```
* Frontend configuration is a checkbox in loginpage
```html
<div class="form-group">
    <label class="control-label col-xs-2" for="remember"> Remember Me? </label>
    <div class="col-xs-10">
        <input id="remember" type="checkbox" name="remember-me" value="true" />
    </div>
</div>
```
* Considerations
    1. basic remember me adds a new cookie `remember` in the browser in addition to `JSESSION`
    2. if `JSESSION` cookie is removed in a *no-remember-me* session then user will be redirected to login page when page is reloaded
    3. if `JSESSION` cookie is removed in a *remember-me* session then user will not be redirected to login page when page is reloaded
    4. remember me cookie lives 2 weeks by default
    5. default cookie es `remember-me` and should go in name attribute of checkbox
    6. other parameters are allowed to change default behavior 

### Cookie configuration
* Default mode of remember me option in spring security is by cookie
* Spring security cookie based configuration
```
base64(username + ":" + expirationTime + ":" +
md5Hex(username + ":" + expirationTime + ":" password + ":" + key))

username:          As identifiable to the UserDetailsService
password:          That matches the one in the retrieved UserDetails
expirationTime:    The date and time when the remember-me token expires, expressed in milliseconds
key:               A private key to prevent modification of the remember-me token
```
* Some othe parameters are
```java
.rememberMe().tokenValiditySeconds(604800).key("demosecapp").rememberMeCookieName("sticky-cookie").rememberMeParameter("remember")
```
  * `.tokenValiditySeconds(604800)`: allow to change expiration date, default is 2 weeks and we can set one week instead
  * `.key("demosecapp")`: secret value that the system use to identify the tokens generated by our application, framework uses this secret value if tokens are valid
  * `.useSecureCookie(true)`: secure the cookie so the cookie is no longer being sent for unsecured connections. In local development is better not to use it because HTTPS. The cookie will existing but will simply be ignored and have no effect.
  * `.rememberMeCookieName("sticky-cookie")`: change the name of the cookie, from the default value of remember-me to any other, the reaon to change the name is to not expose any of the underlying details of the framework we are using to secure our application.
  * `.rememberMeParameter("remember")`: change default value remember-me for the same reason above

### Persistent token configuration
* This is more secure than cookie remember-me because only the `username` is present in the cookie, in other case the `password` is used too
* If something bad happen and cookie is compromised, just delete token in db
* In security config should wire up `DataSource` bean 
* Persistence token is done using the `JdbcTokenRepositoryImpl` of `PersistentTokenRepository` and setting `datasource`
```java
@Autowired
private DataSource dataSource;

@Bean
public PersistentTokenRepository persistentTokenRepository() {
    JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
    jdbcTokenRepository.setDataSource(dataSource);
    return jdbcTokenRepository;
}
```
* Remember me persistence is done by adding `.tokenRepository(persistentTokenRepository())` in `configure(HttpSecurity http)` method
```java
.rememberMe()
    .key("demosecapp")
    .tokenValiditySeconds(604800) // 1 week = 604800
    .tokenRepository(persistentTokenRepository())
    .rememberMeParameter("remember")
```
* Table structure for persistence should be like this (according to [documentation](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#remember-me-persistent-token))
```sql
create table persistent_logins (username varchar(64) not null,
								series varchar(64) primary key,
								token varchar(64) not null,
								last_used timestamp not null)
```
## User credential storage
* concern in protection

## MD5 encoding
* Less secure 
* Is deprecated
* Java configuration in `Security Config` bean
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new Md5PasswordEncoder(); // deprecated MD% password encoder implementation
}
```
* Use in password setting results in MD5 `5f4dcc3b5aa765d61d8327deb882cf99`
```java
user.setPassword(passwordEncoder().encodePassword("password", null));
```
* Security configuration to use password encoder
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
}
```

### Standard encoding - sha-256
* More secure because use sha-256
* Is the standard option 
* Java configuration in `Security Config` bean
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new StandardPasswordEncoder(); // this is the standard enconder sha-256
}
```
* Use in password setting results in sha-256 `5a1ddadef8ea0bfc78ad8572ffe282e2f452f847eb870ae92b4ae79888f014ea253377bfa8c51ab9`
```java
user.setPassword(passwordEncoder().encode("password")); // stardard encoder sha-256
```
* User service that save password shoul wire up `PasswordEncoder` and encode password

### Using SALTS to encoding
* SALT can be saved in db, dont need to be hidden
* SALT should be unique per credential
* SALT should be fixed length
* SALT should be cryptographically strong random value

* Spring security `StandardPasswordEncoder` implementation uses a SALT by default that is secure `class SecureRandomBytesKeyGenerator implements BytesKeyGenerator`
    * This SALT implementation meet above conditions
### Using Bcrypt encoding implementation
* Benefits 
1. Uses built-in salt value, different for each psw
2. Random is a 16 byte value (for salt)
3. Support for key stretching with a slow algorithm
4. Amount of work for key stretching can be set with `strength` parameter wich takes values from 3 to 31 and default value is 10.
5. The higher the strength value, more work has to be done to calculate the hash
6. It is important to know that strength value can be change without affecting existing passwords, because the value is stored in the encoded hash (see below)
* Bcrypt with strength 12
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // implements bcrypt encoder
}
```
* Bcrypt encoding for `password` gives (in this case) `$2a$12$43gaubWA1jlYdi.JOxwGAe/BNopGQbC5ThRws2Gj6W74Mr/fMlhn.`

| part | description |
| --- | --- | 
| $2a$ | indicates bcrypt hash | 
| 12$ | strength | 
| 43gaubWA1jlYdi.JOxwGAe | 22 characters salt |
| /BNopGQbC5ThRws2Gj6W74Mr/fMlhn. | 31 characters hash value |

## Run-as functionality
* Allow you to run some operations under different principal with different authorities without logout and login with different user
* Some scenarios of use
    * System that need to call remote services
    * The need of a temporal privileges elevation of the current logged user (generating a new report that needs to access more data than the user may regularly need to see)
### Implementation
* Configure method security with RunAsManager bean
```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class DemoMethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    @Override
    protected RunAsManager runAsManager() {
        final RunAsManagerImpl runAsManager = new RunAsManagerImpl();
        runAsManager.setKey("MyRunAsKey");
        return runAsManager;
    }
}
```
* Set up new authentication provider for RunAs (note that the key must be the same)
```java
@Bean
public AuthenticationProvider runAsAuthenticationProvider() {
    final RunAsImplAuthenticationProvider authProvider = new RunAsImplAuthenticationProvider();
    authProvider.setKey("MyRunAsKey"); // same as DemoMethodSecurityConfig.runAsManager method
    return authProvider;
}
```
* Should be wired in `AuthenticationManagerBuilder` of `configureGlobal(AuthenticationManagerBuilder auth)` method
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
    auth.authenticationProvider(daoAuthenticationProvider());
    auth.authenticationProvider(runAsAuthenticationProvider());
}
```
* Because the use of an additional authentication provider `userDetailsService` is going to managed from another authentication provider
```java
@Bean
public AuthenticationProvider daoAuthenticationProvider() {
    final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
}
```
* Create a Controller with extra role `@Secured({ "ROLE_USER", "RUN_AS_REPORTER" })`
* Create a Service with method secured with `@Secured({ "ROLE_RUN_AS_REPORTER" })`
* Note that the `RUN_AS_REPORTER` at the Controller level is just a marker role and not an actual role assigned to the user
* This previous `RUN_AS*` marker is converted to the new authority, receives the extra `ROLE_` prefix in the process, and is now available on the current Authentication object

* Finally add new `DemoMethodSecurityConfig.class` to the `SpringSecurityDemoApplication.class`  

## Add custom filter to filter chain of security configuration

* Default filter chain list
1. `WebAsyncManagerIntegrationFilter`
2. `SecurityContextPersistenceFilter`
3. `HeaderWriterFilter`
4. `LogoutFilter`
5. `RequestCacheAwareFilter`
6. `SecurityContextHoldeAwareRequestFilter`
7. `RememberMeAuthenticationFilter`
8. `AnonymousAuthenticationFilter`
9. `SessionManagementFilter`
10. `ExceptionTranslationFilter`
11. `FilterSecurityInterceptor`

* New custom filter must extend `GenericFilterBean` and override `doFilter` method
```java
@Component
public class LoggingFilter extends GenericFilterBean {
    private final Logger log = Logger.getLogger(LoggingFilter.class);

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        
        // some filter logic

        filterChain.doFilter(servletRequest, servletResponse); // implementation
    }
}
```
* To add new custom filter to security config
1. Wire up filter 
```java
@Autowired
private LoggingFilter loggingFilter;
```
2. Set in filter chain (before or after another filter, or let spring set position)
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .addFilterBefore(loggingFilter, AnonymousAuthenticationFilter.class) // add custom LoggingFilter in chain before of AnonymousAuthenticationFilter
        .authorizeRequests()
        // more configuration    
        .csrf().disable()
    ;
}
```
* After configuration filter chain is (custom filter is set before)
1. `WebAsyncManagerIntegrationFilter`
2. `SecurityContextPersistenceFilter`
3. `HeaderWriterFilter`
4. `LogoutFilter`
5. `RequestCacheAwareFilter`
6. `SecurityContextHoldeAwareRequestFilter`
7. `RememberMeAuthenticationFilter`
8. `LoggingFilter`
9. `AnonymousAuthenticationFilter`
10. `SessionManagementFilter`
11. `ExceptionTranslationFilter`
12. `FilterSecurityInterceptor`

## Authentication Providers

### Custom Authentication Provider
* Should implement `AuthenticationProvider` interface if we call to a third party system
* Contract in `authenticate` method of interface
    * if authentication succeeds, a full Authentication object (with credentials) is expected as the return
    * if the provider doesn’t support the Authentication input, it will return null (and the next provider will be tried)
    * if the provider does support it and we attempt authentication and fail - AuthenticationException
```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();

        if (!supportsAuthentication(authentication)) { // check if this implementation manage authentication
            return null;
        }

        /**
         * Check authentication in 3rd party system, if its ok then return credentials in this case
         * if 3rd party system fails then must manage data to send exception. 3rd party system could send more
         * data than simple true or false and this system needs to manage that information in case of throw exception
         * Is better to control all exceptions that you can that are extends from AuthenticationException
         */
        if (doAuthenticationAgainstThirdPartySystem()) { // could do authentication in 3rd party system but in this case just return credentials
            return new UsernamePasswordAuthenticationToken(name, password, new ArrayList<>());
        } else {
            throw new BadCredentialsException("Authentication against the third party system failed");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    //

    private boolean doAuthenticationAgainstThirdPartySystem() {
        return true;
    }

    private boolean supportsAuthentication(Authentication authentication) {
        return true; // becausa this provider will manage authentication
    }
}
```
* Also could extend `AbstractUserDetailsAuthenticationProvider` like `DaoAuthenticationProvider` because handle things like `encoder` and `salt`
* In case an Authentication provider is not handle authentication then let other provider to do it
* Override default provider `auth.userDetailsService(userDetailsService)` in `configureGlobal(AuthenticationManagerBuilder auth)` method
```java
@Autowired
private CustomAuthenticationProvider customAuthenticationProvider;

@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
     //auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()); // this contains by default DaoAuthenticationProvider

    auth.authenticationProvider(customAuthenticationProvider); // should implement encoder and salt but is for simple login
}
```

* `ProviderManager` shows providers list registered in case you want to see if custom provider is being use

### Multiple authentication providers
* This could be done in the `configureGlobal(AuthenticationManagerBuilder auth)` method... i.e 3 providers
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
    auth.authenticationProvider(customAuthenticationProvider); 
    auth.authenticationProvider(daoAuthenticationProvider());
    auth.authenticationProvider(runAsAuthenticationProvider());
}
```

### Authentication manager
* Define an auth manager bean is done in rare advanced cases
* If an auth manager can not authenticate then it goes to the parent
* This let you the possibility to change the hierarchy and plug in a sort of fallback auth manager in case all others fall
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
    auth.parentAuthenticationManager(new ProviderManager(Lists.newArrayList(customAuthenticationProvider)));
}
```
* Also is possible to confgure the auth manager
* By default, the ProviderManager will clear sensitive credentials information from the Authentication object which is returned by a successful authentication request. 
    * This prevents information like passwords being retained longer than necessary.
    * In some rare cases, system need to change that - for example, say we’re storing these authentication objects into a cache (maybe they’re expensive to get back). 
* To disable the clearing of credentials can set next configuration
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    ProviderManager authenticationManager = new ProviderManager(Lists.newArrayList(customAuthenticationProvider));
    authenticationManager.setEraseCredentialsAfterAuthentication(false);
    auth.parentAuthenticationManager(authenticationManager);
}
```
* Is important to keep in mind that the config API allows above configuration without messing with the actual manager bean
```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.eraseCredentials(false).userDetailsService(userDetailsService);
}
```

## Authentication User Storage
### In Memory
* Authentication done with in memory user storage
```java
@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user1").password("password1").roles("USER")
            .and()
            .withUser("user2").password("password2").roles("ADMIN")
        ;
    }
}
```
### Jdbc
* Authentication done with jdbc user storage
```java
@Autowired private DataSource dataSource;

@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter {    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource).withDefaultSchema()
            .withUser("user1").password("password1").roles("USER")
            .and()
            .withUser("user2").password("password2").roles("ADMIN")
        ;
    }
}
```
* `withDefaultSchema()` just work for h2 db, in mysql this wont work because it doesnt have type `varchar_ignorecase`
* Structure for MySQL
```sql
create schema if not exists ssdemo;
USE ssdemo;
create table users(
  username varchar(50) not null primary key, 
  password varchar(500) not null, 
  enabled boolean not null
);
create table authorities (
  username varchar(50) not null, 
  authority varchar(50) not null, 
  constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index ix_auth_username on authorities (username,authority);
```
* With above schema `withDefaultSchema()` configuration is not longer needed
```java
auth.jdbcAuthentication().dataSource(dataSource)
``` 

* For others non standard db structure (own structure) the configuration allows use to set up
```java
.usersByUsernameQuery( ... )
.authoritiesByUsernameQuery( ... )
```

### JPA User Storage
* This is shown in the code and describe it earlier in this documentation

## Troubleshootings

### CSS not found with Thymeleaf and Spring Boot
[Thymeleaf and @EnableWebMvc](https://stackoverflow.com/questions/29562471/springboot-with-thymeleaf-css-not-found)

### Spring Security Context Holder problems hold context in new threads
* SecurityContextHolder is the storage mechanism for the security information associated to the running thread, it uses a ThreadLocal to store de user details which hold a single context per thread, in an Async call that context is lost
* Strategy to propagate security context to new threads:
    *  Pass as environment property as VM Option parameter at startup: `-Dspring.security.strategy=MODE_INHERITABLETHREADLOCAL`
    *  Add to application.properties: `spring.security.strategy=MODE_INHERITABLETHREADLOCAL`
    *  Add programatically: `SecurityContextHolder.setStrategyName("MODE_INHERITABLETHREADLOCAL")`  
* Test if current user pas in new thread
```java
@Async
public void asyncCall() {
    log.info("async call... {}", SecurityContextHolder.getContext().getAuthentication());
}
```
* Security context is mantained between requests (or user operations), in MVC app after login, the user is identified by its session id. 
  the management of the context is done by the `SecurityContextPersistenceFilter`. And by default, it stores the context as an attribute of the HTTP session, 
  and it then restores it for each request and clears it when the request ends.
* If the system is stateless (no session), like in a REST API, `SecurityContextPersistenceFilter` is still needed for this logic.
* [Store security context between requests](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#tech-intro-sec-context-persistence)

## Tracking active users with SessionRegistry interface
* Configuration goes when configuring `HttpSecurity`
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            // configurations
            // ...
            .and()
            .sessionManagement()
                .maximumSessions(1)
                .sessionRegistry(sessionRegistry()) // register this session registry into our security configuration
                .and()
                .sessionFixation().none() // this is need to close the session configuration

            .and()
            // continues remember me configuration
            // and csrf disabling
    ;
}
@Bean
public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
}
```
* Active users can be managed in a service that wire `SessionRegistry`
```java
@Service
public class ActiveUserService {
    private static Logger log = LoggerFactory.getLogger(ActiveUserService.class);

    @Autowired
    private SessionRegistry sessionRegistry; // already wired in BasicSecurityConfig

    public List<String> getAllActiveUsers() {
        //List<User> principals = sessionRegistry.getAllPrincipals(); // return List<Object> (parent) and cannot be casted to List<User> (child)
        List<Object> principals = sessionRegistry.getAllPrincipals();
        User[] users = principals.toArray(new User[principals.size()]); // convert to array of Users

        return Arrays.stream(users)
                .filter(u -> !sessionRegistry.getAllSessions(u, false).isEmpty()) // get active sessions from all sessiones
                .map(u -> u.getUsername()) // get usernames
                .collect(Collectors.toList())
        ;
    }
}
```
* Get active users to view can be done by call service created above
```java
@Autowired private ActiveUserService activeUserService;

@RequestMapping
public ModelAndView list() {
    asyncBean.asyncCall(); // call to asyng method to see what happen with spring security context

    // return just active users
    List<User> users = activeUserService.getAllActiveUsers().stream()
            .map(s -> userRepository.findByEmail(s)).collect(Collectors.toList());

    log.info("users -> {}", users);
    return new ModelAndView("users/list", "users", users);
}
```

## Authorization
### Objects that can be secured
* Web Requests (url requuest) is secured with the `FilterSecurityInterceptor` object
* Method Invocations (method in a class -controller-) objects are secured with the `MethodSecurityInterceptor` object
* Implementations mentioned above extends `AbstractSecurityInterceptor` that has the most part of the interceptor logic
* Main driver in th interceptor logic runs in the `before invocaion` flow that runs before any invocation (web or method)
    1. Get the configuration attributes for the particular request
    2. Attempt to authoriza delegating to `AccessDecisionManager`
        2.1. If access is `granted` then the invocation proceeds
        2.2. If access is `not granted` then throw an `AccessDeniedException`  

#### Securing methods in a centralized way (without annotations)
* Better order and clean keeping security configurations centralized in just one place
* When is not possible annotate sorcer code because there is no access to it and then it cannot be modify it
* Method secured are authorized twice, one by the url (web request) and secondly authorize with the method invocation
* Implementation to secure method invocation using AOP
```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public static class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    @Override
    public MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        final Map<String, List<ConfigAttribute>> methodMap = new HashMap<>(); // map with methods to secure
        methodMap.put("com.maurofokker.demo.web.controller.UserController.createForm*", SecurityConfig.createList("ROLE_ADMIN"));
        return new MapBasedMethodSecurityMetadataSource(methodMap);
    }
}
```
* _Nota_: in order to use role authorities (instead of privileges) `DemoUserDetailsService.getAuthorities` should be implemented
```java
public final Collection<? extends GrantedAuthority> getAuthorities(final Collection<Role> roles) {
    return roles.stream()
            //.flatMap(role -> role.getPrivileges().stream()) // this go deep to privilage level authorities
            .map(p -> new SimpleGrantedAuthority(p.getName())) // commented above line this get first level role authorities
            .collect(Collectors.toList());
}
```
* To debug above a break point can be placed in `AbstractSecurityInterceptor.beforeInvocation(..)` and see what implementation is used

### Auth process
#### `AccessDecisionManager` as the main driver 
* Starter in the authorization flow
* It implementations
1. `AffirmativeBased`: any affirmative vote will grant access
2. `ConsensusBased`: need a majority of affirmative vote to grant access
3. `UnanimousBased`: all affirmative vote are required to grant access (abstains doesn't count)

#### `Voters` in the authorization process
* A Voter is a rule that can grant or restrict access  to a resource 
* Base implementation is `AccessDecisionVoter` allow to implement own logic, but there are a lot of them in the framework
* Some voter implementations
1. `Role`: voter used directly when using Role based authorization
2. Exist one `Hierarchical Role`
3. `Authenticated`: voter that check for authentication when using `isAuthenticated()` expression
4. `Web expressions`: 
5. `ACL`:

##### Implementing a Custom Voter
* Change from `AffirmativeBased` (default) to a more restrictive `UnanimousBased` (where custom voter will be added)
```java
@Bean
public AccessDecisionManager unnanimous(){
    List<AccessDecisionVoter<? extends Object>> voters = Lists.newArrayList(
      new RoleVoter(), new AuthenticatedVoter(), new WebExpressionVoter());
    return new UnanimousBased(voters);
}
```
* Must be wire up to the authotize request
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .antMatchers("/secured").access("hasRole('ADMIN')") // web expression voter secured for specific role
            .antMatchers("/signup"
                    , "/user/register"
                    , "/registrationConfirm*"
                    , "badUser*"
                    , "/forgotPassword*"
                    , "/user/resetPassword*"
                    , "/user/changePassword*"
                    , "/user/savePassword*"
                    , "/js/**"
                ).permitAll() 
            .anyRequest().authenticated()
                        .accessDecisionManager(unnanimous()) // use bean with unnanimous decision manager that add custom voter
        .and()
        
        // configurations..

        .and()
        .csrf().disable()
    ;
}
```
* To create the new voter this need to implement `AccessDecisionVoter<Object>` interface
```java
public class RealTimeLockVoter implements AccessDecisionVoter<Object> { }
```
* Implementation of this in classes `RealTimeLockVoter` (custom voter) and `LockedUsers` (simple cache for users locked)

#### Authorization strategy
* By default
    * `AccessDecisionManager` is `AffirmariveBased`
    * Works with a `RoleVoter` and an `AuthenticatedVoter`
* Above can be changed with configurations and set other voters

#### Authorization flow in a simple setup
* Setup is done to allows everything at the URL and uses method security level (in this case to secure a form)
1. `FilterSecurityInterceptor` is the last in the filter chain and is the entry point to call the AccessDecisionManager in the beforeInvocation call
2. This simply goes over the voters and, if any of the voters deny access, then the AccessDeniedException is thrown. Otherwise, access is granted.
   
* Authorization flow run twitce, first for the url and second for a method secured

### Auth Roles and Privileges
#### Concepts
* Flat topology for authorization means that one or more roles can be assigned to an expression
* Above is not very useful because for every new role that need to access to expression there must compile again the code
* It is better to have a two-level hierarchy topology than a flat one because this contain roles and privileges that can be added to role at runtime
* Main concepts
    * `Privilege`: granular and low-level capability in system
    * `Role`: high-level and user facing
    * `Authority`: `GrantedAuthority` class in spring; apply same concept as `Privilege` 
    * `Permission`: apply same concept as `Privilege`
    * `Right`: apply same concept as `Privilege`  
    * `GranthedAuthority` will be map to a `Privilege` and  a `Role` is a collection of privileges
* Privileges examples
    * `Can see a ...`
    * `Can update ...`
    * `Can delete ...`
    * `Can see all of ...`
* Roles examples
    * `ROLE_ADMIN` -> `{READ_PRIVILEGE, WRITE_PRIVILEGE}`
    * `ROLE_USER` -> `{READ_PRIVILEGE}`
* Relationship
    * `User` and `Role` is many to many
    * `Role` and `Privilege` is many to many
#### Two-Level Implementation
* Add `Role` and `Privilege` entities
```java
@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "roles_privileges", joinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"), inverseJoinColumns = @JoinColumn(name = "privilege_id", referencedColumnName = "id"))
    private Collection<Privilege> privileges;

    private String name;
    
    public Role() {
        super();
    }
    
    public Role(final String name) {
        super();
        this.name = name;
    }

    //  setter getter
}

@Entity
public class Privilege {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    @ManyToMany(mappedBy = "privileges")
    private Collection<Role> roles;

    public Privilege() {
        super();
    }

    public Privilege(final String name) {
        super();
        this.name = name;
    }

    // setters and getters
}
```

* Add roles to `User` entity
```java
@Entity
@PasswordMatches
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @NotEmpty(message = "Username is required.")
    private String email;

    // use annotation to validate passw
    @ValidPassword
    @NotEmpty(message = "Password is required.")
    private String password;

    @Transient
    @NotEmpty(message = "Password confirmation is required.")
    private String passwordConfirmation;

    @Column
    private Boolean enabled;

    private Calendar created = Calendar.getInstance();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"), inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    private Collection<Role> roles;

    // setters and getters
}
```
* Modify `UserDetailsService` to get authorities from user roles
```java
@Transactional
@Service
public class DemoUserDetailsService implements UserDetailsService {
    private static Logger log = LoggerFactory.getLogger(DemoUserDetailsService.class);

    // needed bc there are gonna be persistence work
    // to retrieve user
    @Autowired
    private UserRepository userRepository;

    public DemoUserDetailsService() {
        super();
    }

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        log.info("sercha username: {}", email);
        final User user  = userRepository.findByEmail(email);
        log.info("user -> {}",user.toString());
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        //todo: put enabled as user.getEnabled() after finish feature, by the moment im disabling account validation
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, getAuthorities(user.getRoles()));
    }

    /**
     * wrapping authorities in the format spring security expects
     * add authority in collection
     * @param roles
     * @return
     */
    public final Collection<? extends GrantedAuthority> getAuthorities(final Collection<Role> roles) {
        return roles.stream()
                .flatMap(role -> role.getPrivileges().stream())
                .map(p -> new SimpleGrantedAuthority(p.getName()))
                .collect(Collectors.toList());
    }
}
```
* Create repositories for `Role` and `Privilege`

## References

### Spring Security

1 [Java Configuration in Spring Security](http://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#jc)

2 [Authorization Architecture](https://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#authorization)

3 [Java Config and Form Login in the Spring Security](http://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-form)

4 [Logout in the Spring Security Reference](http://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-logout)

5 [Anonymous Authentication in the Spring Security Reference](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#anonymous)

6 [Registration form](http://www.baeldung.com/spring-security-registration)

7 [Remember me hash token](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#remember-me-hash-token)

8 [Password encoding](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#core-services-password-encoding)

9 [Salt to hash](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#adding-salt-to-a-hash)

10 [Key stretching](https://en.wikipedia.org/wiki/Key_stretching)

11 [Spring Bcrypt](https://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/crypto/bcrypt/BCrypt.html)

12 [Run as Authentication](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#runas)

13 [Add custom filters](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#ns-custom-filters)

14 [Using others authentication providers with XML](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#ns-auth-providers)

15 [AuthenticationManager, ProviderManager and AuthenticationProvider](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#core-services-authentication-manager)

16 [Authentication user storage - inmemory, jdbc and jpa](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#jc-authentication)

17 [Authorization the Default AccessDecisionManager](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#ns-access-manager)

18 [Authorization Pre-Invocation Handling](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#authz-pre-invocation)

19 [Role and Privilege in spring](http://www.baeldung.com/role-and-privilege-for-spring-security-registration)

20 [Secured method invocation with AOP](https://docs.spring.io/autorepo/docs/spring-security/current/reference/htmlsingle/#aop-alliance)

### Persistence

1 [Spring Data Jpa](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/)

2 [Introduction to jpa with spring boot data jpa](http://www.springboottutorial.com/introduction-to-jpa-with-spring-boot-data-jpa)