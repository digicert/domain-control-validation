package com.digicert.validation.repository;

import com.digicert.validation.repository.entity.DomainEntity;
import org.springframework.data.repository.CrudRepository;

public interface DomainsRepository extends CrudRepository<DomainEntity, Long> {
}
