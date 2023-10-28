package com.rtt.realtalktalk.user.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Date;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Builder
@Table(name = "user")
public class UserDomain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Long user_num;

    @Column(nullable = false, length = 100)
    private String user_email;

    @Column(nullable = false, length = 255)
    private String user_password;

    @Column(nullable = false, length = 100)
    private String user_name;

    @Column(nullable = false, length = 1)
    private int user_gender;

    @Column(nullable = false)
    private Date user_regdate;

}
