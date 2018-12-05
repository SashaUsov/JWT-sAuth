# Защита RESTful API с помощью JWT

JSON Web Tokens, широко известен как JWT, является токеном, который используют для аутентификации пользователей в приложениях. Эта технология завоевала популярность в течение последних нескольких лет, поскольку она позволяет бэкендам принимать заявки просто путем проверки содержания этих JWTs. То есть приложениям, использующим JWTs, больше не нужно хранить файлы cookie или другие данные сеанса о своих пользователях. Эта характеристика обеспечивает масштабируемость при сохранении приложений.

Во время процесса аутентификации, когда пользователь успешно выполняет вход в систему с использованием своих учетных данных, возвращается веб-маркер JSON и должен быть сохранен локально (обычно в локальном хранилище). Всякий раз, когда пользователь хочет получить доступ к защищенному маршруту или ресурсу (конечной точке), пользовательский агент должен отправить JWT, как правило, в заголовок авторизации, используя схему Bearer, вместе с запросом.

Когда сервер получает запрос с помощью JWT, первое, что он делает, это проверяет токен. Это состоит из ряда этапов, и если какой-либо из них не выполняется, запрос должен быть отклонен. В следующем списке показаны шаги проверки:

- Убедитесь, что JWT хорошо сформирован
- Проверить подпись
- Подтвердить стандартные претензии
- Проверьте разрешения клиента (области действия)

Основой для реализации JWT аутентификации будет заранее подготовленное базовое приложение, которое вы можете клонировать из моего [git репозитория](https://github.com/SashaUsov/testJWT.git). 

Для начала, внесем несколько правок в уже имеющийся код: 

1. Добавим к этому интерфейсу метод, называемый findByUserName. Этот метод будет использоваться, когда мы реализуем функцию аутентификации. 

```java
package testJWT.demo.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import testJWT.demo.domain.ApplicationUser;

public interface UserRepo extends JpaRepository<ApplicationUser, Long> {

    ApplicationUser findByUserName(String userName);
}
```

2. Шифрование паролей при регистрации. Изменение внесем в MainService

```java
package testJWT.demo.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import testJWT.demo.domain.ApplicationUser;
import testJWT.demo.domain.dto.CreateUserModel;
import testJWT.demo.repo.UserRepo;

@Service
public class MainService {

    private final UserRepo userRepo;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public MainService(UserRepo userRepo,
                       BCryptPasswordEncoder bCryptPasswordEncoder
    ) {
        this.userRepo = userRepo;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public String getGreeting() {

        return "You could and created JWT authentication!";
    }

    public ApplicationUser create(CreateUserModel userModel) {

        ApplicationUser applicationUser = new ApplicationUser();

        applicationUser.setUserName(userModel.getUserName());
        applicationUser.setPassword(bCryptPasswordEncoder.encode(userModel.getPassword()));

        return userRepo.save(applicationUser);
    }
}
```

Реализация этой точки довольно проста. Все, что здесь происходит, это шифрование пароля нового пользователя (оставлять его как обычный текст будет плохой идеей), а затем его сохранение в базе данных. Процесс шифрования обрабатывается экземпляром BCryptPasswordEncoder, который является классом, который относится к структуре Spring Security.

Сейчас в нашем приложении появилось две проблемы:

- Мы не включили систему Spring Security в зависимость нашего проекта.
- Не существует экземпляра BCryptPasswordEncoder по умолчанию, который может быть введен в класс MainService.

Первая проблема, которую мы решим, добавим зависимость структуры Spring Security к файлу ./build.gradle:

```java
	compile('org.springframework.boot:spring-boot-starter-security')
```

Вторую проблему, отсутствующий экземпляр BCryptPasswordEncoder, мы решаем путем реализации метода, который генерирует экземпляр BCryptPasswordEncoder. Этот метод должен быть аннотирован с помощью @Bean, и мы добавим его в класс DemoApplication:

```java
package testJWT.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class DemoApplication {

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}
}
```

Эти изменения завершают функцию регистрации пользователя, но нам по-прежнему не хватает поддержки аутентификации пользователей и авторизации. Давайте же перейдем к ним.

### Аутентификация пользователя и авторизация Spring Boot

Для имплементации аутентификации и авторизации в нашем приложении, мы собираемся:

- внедрить фильтр аутентификации для выдачи JWTs пользователям, отправляющим учетные данные,
- внедрить фильтр авторизации для проверки запросов, содержащих JWTs,
- создать пользовательскую реализацию UserDetailsService, чтобы помочь Spring Security загружать пользовательские данные в структуру,
- расширить класс WebSecurityConfigurerAdapter, чтобы настроить инфраструктуру безопасности для наших нужд.

Прежде чем приступать к разработке этих фильтров и классов, давайте создадим новый пакет security. Этот пакет будет содержать весь код, связанный с безопасностью нашего приложения.

#### Authentication Filter

Первым элементом, который мы реализуем, будет класс, ответственный за процесс аутентификации. Назовем его JWTAuthenticationFilter, и он будет иметь следующий вид:

```java
package testJWT.demo.security;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import testJWT.demo.domain.ApplicationUser;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static testJWT.demo.security.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            ApplicationUser creds = new ObjectMapper()
                    .readValue(req.getInputStream(), ApplicationUser.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUserName(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        String token = JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }
}
```

Обратите внимание, что созданный нами фильтр аутентификации расширяет класс UsernamePasswordAuthenticationFilter. Когда мы добавляем новый фильтр в Spring Security, мы можем явно определить, где в цепочке фильтров мы хотим его видеть, или можем позволить структуре понять это самостоятельно. Расширяя фильтр, предусмотренный в рамках безопасности, Spring может автоматически идентифицировать лучшее место для его размещения в цепочке безопасности.

Наш собственный фильтр аутентификации переопределяет два метода наследуемого класса:

- attemptAuthentication: где мы анализируем учетные данные пользователя и отправляем их в AuthenticationManager.
- successAuthentication: метод, который вызывается при успешном входе в систему пользователя. Мы используем этот метод для создания JWT для данного пользователя.

Наша IDE, вероятно, будет ругаться на код в этом классе по двум причинам. Во-первых, поскольку код импортирует четыре константы из класса, который мы еще не создали, SecurityConstants. Во-вторых, поскольку этот класс генерирует JWTs с помощью класса JWT, который принадлежит библиотеке, которую мы не добавили в качестве зависимости в наш проект.

Решаем эту проблему. В файле ./build.gradle добавим следующую строку кода:

```java
	compile("com.auth0:java-jwt:3.4.0")
```

Это добавит Java JWT: JSON Web Token для Java и Android-библиотеки в наш проект и решит проблему с отсутствующими классами. Теперь нам нужно создать класс SecurityConstants:

```java
package testJWT.demo.security;

class SecurityConstants {
    static final String SECRET = "SecretKeyToGenJWTs";
    static final long EXPIRATION_TIME = 864_000_000; // 10 days
    static final String TOKEN_PREFIX = "Bearer ";
    static final String HEADER_STRING = "Authorization";
    static final String SIGN_UP_URL = "/main/registration";
}
```

Этот класс содержит все четыре константы, на которые ссылается класс JWTAuthenticationFilter, наряду с константой SIGN_UP_URL, которая будет использоваться позже.

#### Authorization Filter

Поскольку мы внедрили фильтр, ответственный за аутентификацию пользователей, теперь нам нужно внедрить фильтр, отвечающий за авторизацию пользователя. Мы создаем этот фильтр как новый класс, называемый JWTAuthorizationFilter, в пакете package testJWT.demo.security:

```java
package testJWT.demo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static testJWT.demo.security.SecurityConstants.HEADER_STRING;
import static testJWT.demo.security.SecurityConstants.SECRET;
import static testJWT.demo.security.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // parse the token.
            String user = JWT.require(Algorithm.HMAC512(SECRET.getBytes()))
                    .build()
                    .verify(token.replace(TOKEN_PREFIX, ""))
                    .getSubject();

            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            return null;
        }
        return null;
    }
}
```

Мы расширили BasicAuthenticationFilter, чтобы Spring заменил его в цепочке фильтров нашей пользовательской реализацией. Самой важной частью фильтра, который мы реализовали, является частный метод getAuthentication. Этот метод читает JWT из заголовка авторизации, а затем использует JWT для проверки токена. Если все на месте, мы устанавливаем пользователя в SecurityContext и позволяем двигаться дальше.

#### Интеграция фильтров безопасности в Spring Boot

Теперь, когда мы создали оба фильтра безопасности, мы должны настроить их в цепочке фильтров Spring Security. Для этого мы создадим новый класс WebSecurity в пакете package testJWT.demo.security:

```java
package testJWT.demo.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Bean;
import testJWT.demo.service.UserDetailsServiceImpl;

import static testJWT.demo.security.SecurityConstants.SIGN_UP_URL;


@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private UserDetailsServiceImpl userDetailsService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public WebSecurity(UserDetailsServiceImpl userDetailsService,
                       BCryptPasswordEncoder bCryptPasswordEncoder
    ) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}

```

Мы аннотировали этот класс с помощью @EnableWebSecurity и расширили WebSecurityConfigurerAdapter, чтобы воспользоваться конфигурацией веб-безопасности по умолчанию, предоставляемой Spring Security. Это позволяет нам подстраивать структуру к нашим потребностям, определяя три метода:

- configure (HttpSecurity http): метод, в котором мы можем определить, какие ресурсы являются общедоступными а которые защищены. В нашем случае мы устанавливаем конечную точку SIGN_UP_URL как общедоступную и все остальное как защищенные. Мы также настраиваем поддержку CORS (Cross-Origin Resource Sharing) через http.cors () и добавляем специальный фильтр безопасности в цепочке фильтров Spring Security.

- configure (AuthenticationManagerBuilder auth): метод, в котором мы определили пользовательскую реализацию UserDetailsService для загрузки пользовательских данных в инфраструктуру безопасности. Мы также использовали этот метод для установки метода шифрования, используемого нашим приложением (BCryptPasswordEncoder).

- corsConfigurationSource (): метод, в котором мы можем разрешить / ограничить поддержку CORS. В нашем случае мы оставили его широко открытым, разрешив запросы из любого источника (/ **).

Spring Security не имеет конкретной реализации UserDetailsService, которую мы могли бы использовать. Поэтому мы создаем новый класс UserDetailsServiceImpl в пакете package testJWT.demo.service:

```java
package testJWT.demo.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import testJWT.demo.domain.ApplicationUser;
import testJWT.demo.repo.UserRepo;

import static java.util.Collections.emptyList;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private UserRepo userRepo;

    public UserDetailsServiceImpl(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ApplicationUser applicationUser = userRepo.findByUserName(username);
        if (applicationUser == null) {
            throw new UsernameNotFoundException(username);
        }
        return new User(applicationUser.getUserName(), applicationUser.getPassword(), emptyList());
    }
}
```

Единственным методом, который мы должны были реализовать, является loadUserByUsername. Когда пользователь пытается аутентифицироваться, этот метод получает имя пользователя, выполняет поиск в базе данных для записи, содержащей его, и (если найден) возвращает экземпляр пользователя. Затем свойства этого экземпляра (имя пользователя и пароль) проверяются на учетные данные, переданные пользователем в запросе на вход. Последний процесс выполняется вне этого класса с помощью среды Spring Security.

Теперь мы можем быть уверены, что наши конечные точки не будут публично раскрыты и что мы сможем правильно поддерживать аутентификацию и авторизацию с помощью JWTs на Spring Boot. Чтобы проверить все, запустите приложение (через IDE или через gradle bootRun) и выполните следующие запросы(я использую Postman):

- для регистрации пользователя отправте по адресу http://localhost:8080/main/registration следующий POST JSON запрос:
    
      { "userName": "admin", "password": "1234567"}

- для получения jwt-token аутентификации по url http://localhost:8080/login шлем такой же POST JSON запрос. В ответ мы получим от сервера token аутентификации содержищийся в заголовке ответа. Его вид будет приблизительно таким :

      Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTU0NDg4NzczN30.VspMpej6kvo7yDuttyfW11JI8hR94e79XQSGwpTuFSLBCRwWtjYPBKkhUQRtRWjZVuEqFSrjSDSDx3s46Y0HWA

Вставив данный токен в заголовок своего GET запроса по адресу http://localhost:8080/main/greeting в ответ мы получим сторку

      You could and created JWT authentication!
      
И это уже будет чистая правда :)
