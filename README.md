.README.md
# Server Side Rendering project
<hr>

## spring security flow
loginProcessingUrl 함수를 통해 spring security가 로그인을 낚아챌 수 있도록 한다.<br>
로그인이 완료되면 security session을 만들어 준다.(key값으로 Security ContextHolder를 가진다.)<br>
그리고 여기에 해당하는 value는 특정 Object 만을 가질 수 있는데, 그것이 Authentication 타입의 객체이다.<br>
그리고 이 Authentication 안에 User 정보를 가지고 있다. 그리고 이 User 정보는 UserDetails 객체이다.<br>

Security session => Authentication => UserDetails<br>
> 여기서 Authentication이 UserDetailsService, UserDetails는 UserDetails를 의마한다 !!

login 요청이 오면 자동으로 UserDetailsService 타입으로 등록되어 있는 서비스의 loadUserByUsername 함수가 실행된다.<br>
loadUserByUsername 함수가 return 하는 값은 Authentication 내부로 들어간다. 즉 Authentication 내부로 리턴!<br>
그 후에 Authentication은 session 내부로 들어간다.

## @Bean
@Bean annotation은 <i>"해당 메서드가 반환하는 오브젝트"</i> 를 IOC에 등록해준다!

## redirect:/
spring MVC에서 redirect:/something 으로 반환값을 주면 something 이라는 주소로 리다이렉트 시켜준다.<br>
```java
return "redirect:/login/error"
```
위와 같은 return 값을 주면

```java
import @GetMapping("/login/error")
public String loginError(Model model) {
    model.addAttribute("errorMessage", "아이디 또는 비밀번호 오류입니다.");
    return "login";
}
```
해당 함수를 실행시켜 url이 /login/error 로 이동하고, View는 login.html view 를 보여주게 된다!!


## 로그인이 계속해서 안됐던 이유!
SSR로 넘어오고, spring security를 이용한 로그인을 다루는데 회원가입은 정상적으로 이루어졌으나 로그인을 하려고 하면
> Resolved [org.springframework.web.HttpRequestMethodNotSupportedException: Request method 'POST' not supported]

이렇게 POST 형식은 지원하지 않는다는 오류가 생겼다. 그리고 View 내에서는 405 error white label page가 보였다.

이거 해결하려고
1. csrf disable
2. csrf ignoringAntMatchers
3. hidden input tag 추가

등 별짓을 다했는데 안되었다.

근데 갑작스럽게 해결하게 되었는데.....

#### 문제는 Authentication에 담을 UserDetails의 기본 함수를 overriding 하는 과정에 있었다.

UserDetails를 구현하는 객체는 필수적으로 overriding 해야 하는 함수가 있다.<br>
getAuthorities, getPassword, getUsername 등 많이 있다. 그리고 boolean type을 반환하는 함수도 있는데 내가 이걸 그냥 지나친 것이 큰 문제였다.

isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled 이렇게 네 가지 함수가 있는데 이 모든 함수의 반환값을 true 로 하니 정상적으로 로그인되었다.

원인을 꼭 찾아보자!!

## /logout 404 error
로그인 기능을 구현한 후 logout을 해보니 404 error가 발생했다.<br>
그 이유는 Spring Security는 기본적으로 CSRF를 막기 위해 활성화 되어 있는데, 이것이 Post 방식으로 들어오는 데이터를 막는 것이다.<br>
csrf().disable()로 간단하게 해결할 수 있다.
> ignoringAntMatchers는 안됨!!

## 현재 로그인한 user의 정보
현재 로그인되어 있는 user의 정보를 가져올 수 있다. 나는 컨트롤러에서 해당 유저의 정보를 가져오는 방법을 채택했다.
```java
import org.springframework.security.core.annotation.AuthenticationPrincipal;

public class UserController {
    public String index(@AuthenticationPrincipal MemberDetails memberDetails, Model model) {
        if (memberDetails != null) {
            System.out.println("member details is not null!");
            System.out.println(memberDetails.getUsername());
        } else {
            System.out.println("member details is null!");
        }
        model.addAttribute("loginInfo", memberDetails);
        return "index";
    }
}
```
Controller 에서 Principal을 이용하여 사용자 정보를 받는 방법도 있는데, 이건 getName()만 가능해서 뺌!!

추가로 Bean 에서 사용자 정보를 얻을 수도 있다. (나중에 유용하게 사용할 수 있을듯!)
```java
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
UserDetails userDetails = (UserDetails)principal;

String username = principal.getUsername();
String password = principal.getPassword();
```

## failureUrl vs failureForwardUrl ??

<hr>

# Spring Security Token With JWT
## Entity Class data 중 column에 포함시키지 않기
@Transient annotaion을 이용하면 Entity class의 데이터 중에서, database table의 column에 추가시키지 않을 데이터를 선택할 수 있다.
```java
@Entity
@Table(name = "users")
public class User {
    // @Transient: 해당 데이터를 column과 매핑시키지 않는다.
    @Transient
    Collection<? extends GrantedAuthority> authorities;
}
```
## Cookie -> NullPointerException
JWT를 이용한 토큰 방식 구현 중, status 500의 에러가 났다.<br>
가장 일반적이고 범위가 넓은 500 error가 나와 당황했었는데, error message를 보니 JwtRequestFilter에서 request의 cookies를 읽어오는 과정에서
NullPointerException이 발생했다.

```java
Arrays.stream(request.getCookies())
```
처음엔 쿠키가 존재하지 않아 request.getCookies()는 null을 반환하고, 이 null 값을 가지고 handling 하다 보니 error가 난 것이었다.

따라서 request.getCookies()를 통해 cookie 들을 읽어오는 전반적인 과정을 try catch 문을 이용하여 예외처리 해주니 정상적으로 작동했다.

## Cookie String Rule
톰캣 8.5에서 새로 추가된 기본 쿠키 규칙이 있다.
> An invalid character [32] was present in the Cookie value] with root cause

쿠키에 사용될 수 없는 값으로 <kbd>;</kbd><kbd>,</kbd><kbd>=</kbd><kbd> (공백)</kbd>이 사용될 수 없다.<br>
쿠키 값의 앞부분에 "bearer " 스트링을 추가해서 생긴 오류. <kbd>_</kbd>로 해결했다.

# Simple Error Report
> Content type 'application/x-www-form-urlencoded;charset=UTF-8' not supported

form 태그에서 submit 으로 데이터를 전달할 때 발생. @RequestBody annotation 제거 또는 Dto 사용

# <i>하단의 내용은 [carework-web-page](https://github.com/dldudals0728/carework-web-page)의 README.md 참고</i>