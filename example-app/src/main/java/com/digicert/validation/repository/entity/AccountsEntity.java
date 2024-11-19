package com.digicert.validation.repository.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class AccountsEntity {
    @Id
    @Column(name = "account_id")
    public long accountId;

    @Column(name = "token_key")
    public String tokenKey;
}
