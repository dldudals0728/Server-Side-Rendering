package com.SSR.CTSoft.Thymeleaf.jwt;

import com.SSR.CTSoft.Thymeleaf.entity.RefreshToken;
import com.SSR.CTSoft.Thymeleaf.entity.User;
import com.SSR.CTSoft.Thymeleaf.repository.RefreshTokenRepository;
import com.SSR.CTSoft.Thymeleaf.repository.UserRepository;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private static String secret = "leeyoungmin";

    // 5분 단위(for test)
    public static final long JWT_TOKEN_VALIDITY = 1000 * 60 * 5;

    // token 으로 사용자 id 조회
    public String getUsernameFromToken(String token) {
        return this.getClaimFromToken(token, Claims::getId);
    }

    // token 으로 사용자 속성정보 조회
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = this.getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // 모든 token 에 대한 사용자 속성정보 조회
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    // token 만료 여부 체크
    private Boolean isTokenExpired(String token) {
        final Date expiration = this.getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    // token 만료일자 조회
    public Date getExpirationDateFromToken(String token) {
        return this.getClaimFromToken(token, Claims::getExpiration);
    }

    // id 를 입력받아 accessToken 생성
    public String generateAccessToken(String id) {
        return this.generateAccessToken(id, new HashMap<>());
    }

    // id, 속정정보를 이용해 accessToken 생성
    public String generateAccessToken(String id, Map<String, Object> claims) {
        return this.doGenerateAccessToken(id, claims);
    }

    // JWT accessToken 생성
    private String doGenerateAccessToken(String id, Map<String, Object> claims) {
        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setId(id)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))   // 5분
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        return accessToken;
    }

    // id 를 입력받아 refreshToken 생성
    public String generateRefreshToken(String id) {
        return this.doGenerateRefreshToken(id);
    }

    // JWT refreshToken 생성
    private String doGenerateRefreshToken(String id) {
        String refreshToken = Jwts.builder()
                .setId(id)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 6))   // 30분
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        return refreshToken;
    }

    // id 를 입력받아 accessToken, refreshToken 생성
    public Map<String, String> generateTokenSet(String id) {
        return this.generateTokenSet(id, new HashMap<>());
    }

    // id, 속성 정보를 이용해 accessToken, refreshToken 생성
    public Map<String, String> generateTokenSet(String id, Map<String, Object> claims) {
        return this.doGenerateTokenSet(id, claims);
    }

    // JWT accessToken, refreshToken 생성
    private Map<String, String> doGenerateTokenSet(String id, Map<String, Object> claims) {
        Map<String, String> tokens = new HashMap<>();

        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setId(id)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))   // 5분
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        String refreshToken = Jwts.builder()
                .setId(id)
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 6))   // 30분
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;
    }

    // JWT refreshToken 만료체크 후 재발급
    public Boolean reGenerateRefreshToken(String id) throws Exception {
        System.out.println("[reGenerateRefreshToken] refreshToken 재발급 요청");

        // DB 에서 관리자 정보 조회
        User user = userRepository.findByUsername(id);
        long userIdx = user.getId();

        // DB에서 refreshToken 정보 조회
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByUserIdx(userIdx);

        // refreshToken 정보가 존재하지 않는 경우
        if (refreshTokenEntity == null) {
            System.out.println("[reGenerateRefreshToken] refreshToken 정보가 존재하지 않습니다.");
            return false;
        }

        // refreshToken 만료 여부 체크
        try {
            String refreshToken = refreshTokenEntity.getRefreshToken().substring(7);
            Jwts.parser().setSigningKey(secret).parseClaimsJws(refreshToken);
            System.out.println("[reGenerateRefreshToken] refreshToken 이 만료되지 않았습니다.");
            return true;
        }
        // refreshToken 이 만료된 경우 재발급
        catch (ExpiredJwtException e) {
            refreshTokenEntity.setRefreshToken("Bearer_" + this.generateRefreshToken(id));
            refreshTokenRepository.save(refreshTokenEntity);
            System.out.println("[reGenerateRefreshToken] refreshToken 재발급 완료 : " + "Bearer_" + this.generateRefreshToken(id));
            return true;
        }
        // 그 외 예외처리
        catch (Exception e) {
            System.out.println("[reGenerateRefreshToken] refreshToken 재발급 중 문제 발생 : " + e.getMessage());
            return false;
        }
    }

    // token 검증
    public Boolean validateToken(String token, User user) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            System.out.println("JwtTokenProvider");
            System.out.println("invalid Jwt signature : " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("JwtTokenProvider");
            System.out.println("invalid Jwt token : " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JwtTokenProvider");
            System.out.println("JWT token is expired : " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JwtTokenProvider");
            System.out.println("JWT token is unsupported : " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JwtTokenProvider");
            System.out.println("JWT claims string is empty : " + e.getMessage());
        }

        return false;
    }
}
