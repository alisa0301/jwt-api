package com.enablebanking.jwtapi.dto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtInfo {
    Claims claims;
    JwsHeader header;
}
