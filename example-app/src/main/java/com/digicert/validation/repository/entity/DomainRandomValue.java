package com.digicert.validation.repository.entity;

import jakarta.persistence.*;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
public class DomainRandomValue {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public long id;

    @Column(name = "random_value")
    public String randomValue;

    @Column(name = "email")
    public String email;

    @ManyToOne
    @JoinColumn(name = "domain_id", referencedColumnName = "id")
    public DomainEntity domain;

    public DomainRandomValue(String randomValue, String email, DomainEntity domain) {
        this.randomValue = randomValue;
        this.email = email;
        this.domain = domain;
    }
}
