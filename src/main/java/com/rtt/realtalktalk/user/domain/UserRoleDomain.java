package com.rtt.realtalktalk.user.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "user_role")
public class UserRoleDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long role_num;

    @Column(nullable = false)
    private Long user_num;

    @Column(nullable = false, length = 50)
    private String role_name;
}
