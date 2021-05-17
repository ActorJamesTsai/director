package com.avenger.director.domain.user;

import com.avenger.actor.domain.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Description:
 *
 * Date: 2021/5/16
 *
 * @author JiaDu
 * @version 1.0.0
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class User extends BaseEntity {


    private Long id;

    private String userId;

    private String userName;

    private String password;

    private String phoneNumber;

    private Integer status;
}
