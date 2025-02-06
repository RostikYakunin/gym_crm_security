package com.crm.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
@Builder
public class Token {
    private String ownerUserName;
    private Date issuedAt;
    private Date expiredAt;
    private String token;
}
