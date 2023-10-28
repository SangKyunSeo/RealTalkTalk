package com.rtt.realtalktalk.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserReqDto {
    private Long user_num;
    private String user_email;
    private String user_password;
    private String user_name;
    private int user_gender;
    private Date user_regdate;
}
