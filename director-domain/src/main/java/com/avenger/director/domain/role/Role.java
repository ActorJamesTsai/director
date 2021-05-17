package com.avenger.director.domain.role;

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
public class Role extends BaseEntity {

    private Long id;

    private String roleId;

    private String roleName;

    private Integer status;
}
