package com.rentacar.car_rental.repository;

import com.rentacar.car_rental.domain.Role;
import com.rentacar.car_rental.domain.enumeration.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(UserRole name);

}
