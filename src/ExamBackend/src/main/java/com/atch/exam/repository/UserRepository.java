package com.atch.exam.repository;

import com.atch.exam.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.role = 'ROLE_STUDENT' AND (LOWER(u.username) LIKE LOWER(CONCAT('%', :query, '%')) OR CAST(u.id AS string) LIKE CONCAT('%', :query, '%'))")
    List<User> searchStudents(@Param("query") String query);

    java.util.Optional<User> findByUsername(String username);
}
