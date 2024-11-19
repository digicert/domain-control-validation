package com.digicert.validation.repository;

import com.digicert.validation.repository.entity.AccountsEntity;
import org.springframework.data.repository.CrudRepository;

public interface AccountsRepository extends CrudRepository<AccountsEntity, Long> {
}
