package com.rentacar.car_rental.controller;

import com.rentacar.car_rental.domain.User;
import com.rentacar.car_rental.security.jwt.JwtUtils;
import com.rentacar.car_rental.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.Map;

@AllArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@Produces(MediaType.APPLICATION_JSON)
@RequestMapping()
public class UserController {

    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JwtUtils jwtUtils;

    @PostMapping("/user/register")
    public ResponseEntity<Map<String, Boolean>> registerUser(@Valid @RequestBody User user){
        userService.register(user);

        Map<String, Boolean> map = new HashMap<>();
        map.put("User registered successfully!", true);

        return new ResponseEntity<>(map, HttpStatus.CREATED);
    }

    @PostMapping("/user/login")
    public ResponseEntity<Map<String, String>> authenticationUser(@RequestBody Map<String, Object> userMap){
        String username = (String) userMap.get("username");
        String password = (String) userMap.get("password");

        userService.login(username, password);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username,password));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        Map<String, String> map = new HashMap<>();
        map.put("token", jwt);

        return new ResponseEntity<>(map, HttpStatus.OK);
    }










}
