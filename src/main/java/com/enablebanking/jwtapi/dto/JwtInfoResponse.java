package com.enablebanking.jwtapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtInfoResponse {
    private JwtInfo jwt;
}

@Data
@NoArgsConstructor
@AllArgsConstructor
class JwtInfo {
    private JwtHeaderInfo header;
}

@Data
@NoArgsConstructor
@AllArgsConstructor
class JwtHeaderInfo {
    private String alg;
}
