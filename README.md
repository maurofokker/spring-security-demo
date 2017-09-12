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
* replace basic auth with default login form config (auto generated in this case)
* is possible to override auto generated form

## References

[Java Configuration in Spring Security](http://docs.spring.io/spring-security/site/docs/4.0.4.RELEASE/reference/htmlsingle/#jc)