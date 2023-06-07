package com.cos.security.repository;

import com.cos.security.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long> {

    public User findByUsername(String username);
}
