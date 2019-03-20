# JWT security autoconfigure

[![Build Status Master](https://dev.azure.com/cobrijani0641/jwt-security-spring-boot-starter/_apis/build/status/Cobrijani.jwt-security-spring-boot-starter?branchName=master)](https://dev.azure.com/cobrijani0641/jwt-security-spring-boot-starter/_build/latest?definitionId=1&branchName=master)
[![Build Status Development](https://dev.azure.com/cobrijani0641/jwt-security-spring-boot-starter/_apis/build/status/Cobrijani.jwt-security-spring-boot-starter?branchName=development)](https://dev.azure.com/cobrijani0641/jwt-security-spring-boot-starter/_build/latest?definitionId=1&branchName=development)

- Represents Auto-configured Spring Security on Jwt based authentication for spring boot monolith applications



- __Maven__:
  ```xml
        <dependency>
            <groupId>com.github.cobrijani</groupId>
            <artifactId>jwt-security-spring-boot-starter</artifactId>
            <version>0.0.3</version>
        </dependency>
  ```

- __Gradle__

```groovy
compile('com.github.cobrijani:jwt-security-spring-boot-starter:0.0.3')
```
To use it:

1. Get dependency

2. Implement project specific classes below:
  - ```org.springframework.security.core.userdetails.UserDetails```
  - ```org.springframework.security.core.userdetails.UserDetailsService```

3. POST on '/api/v1/login' with request body as below

```json
  {
      "login": "user login in db or w/e",

      "password": "user password",

      "isRememberMe": "remember me"
  }

```

4. If 'UserDetails' and 'UserDetailsService' are successfully implement according to your project you should get
    something like this
 ```json
    {
    "id_token": "your jwt"
    }

 ```


