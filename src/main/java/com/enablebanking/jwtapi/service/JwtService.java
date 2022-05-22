package com.enablebanking.jwtapi.service;

import com.enablebanking.jwtapi.config.JwtCredentialsConfig;
import com.enablebanking.jwtapi.dto.JwtInfo;
import com.enablebanking.jwtapi.dto.JwtInfoResponse;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {
    private final static String AUTH_HEADER = "Authorization";
    private final static String AUTH_TYPE = "Bearer";
    private static final int JWT_START_POSITION = AUTH_TYPE.length() + 1;
    private final static int JWT_EXPIRATION_MS = 1000 * 60 * 60 * 10;

    private final JwtCredentialsConfig credentialsConfig;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        /**
         * Private key and certificate files are in PKCS1 format.
         * We need in PKCS8
         */
        Security.addProvider(new BouncyCastleProvider());
        privateKey = readPrivateKey();
        publicKey = readPublicKey();
    }

    private PrivateKey readPrivateKey() {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(credentialsConfig.getPrivateKey())
            );
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private PublicKey readPublicKey() {
        try {
            CertificateFactory kf = CertificateFactory.getInstance("X.509");
            Certificate crt = kf.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(credentialsConfig.getCert()))
            );
            return crt.getPublicKey();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateToken(UserDetails userDetails) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + JWT_EXPIRATION_MS))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String userName = extractUserName(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaimes(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaimes(String token) {
        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
    }

    public JwtInfoResponse getClaims(String token) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
        JwsHeader header = claimsJws.getHeader();
        Claims body = claimsJws.getBody();
        return JwtInfoResponse.builder()
                .jwt(JwtInfo.builder()
                        .claims(body)
                        .header(header)
                        .build())
                .build();
    }

    public String getJwtFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith(AUTH_TYPE)) {
            return authHeader.substring(JWT_START_POSITION);
        }
        return null;
    }
}
