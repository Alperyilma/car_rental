package com.rentacar.car_rental.repository;

import com.rentacar.car_rental.domain.User;
import com.rentacar.car_rental.exception.BadRequestException;
import com.rentacar.car_rental.exception.ConflictException;
import com.rentacar.car_rental.exception.ResourceNotFoundException;
import com.rentacar.car_rental.projection.ProjectUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User>findByEmail(String username) throws ResourceNotFoundException;

    Boolean existsByEmail(String email) throws ConflictException;

    List<ProjectUser> findAllBy();

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.firstName = ?2, u.lastName = ?3, u.phoneNumber = ?4, " +
            "u.email = ?5, u.address = ?6, u.zipCode = ?7 WHERE u.id = ?1")
    void update(Long id, String firstName, String lastName, String phoneNumber,
                String email, String address, String zipCode) throws BadRequestException;


}
