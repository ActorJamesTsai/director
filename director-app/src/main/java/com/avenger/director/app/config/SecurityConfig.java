package com.avenger.director.app.config;

import cn.hutool.core.util.StrUtil;
import com.avenger.director.app.kit.JoseKit;
import java.security.Key;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Description:
 *
 * Date: 2021/5/16
 *
 * @author JiaDu
 * @version 1.0.0
 */
@Configuration
@ConfigurationProperties(prefix = "sso.security")
public class SecurityConfig {

    private String header;

    /**
     * 令牌前缀，最后留个空格 Bearer
     */
    private String tokenStartWith;

    private String signSecurity;

    private String encryptionSecurity;


    public String getSignSecurity() {
        return this.signSecurity;
    }

    public void setSignSecurity(String signSecurity) {
        this.signSecurity = signSecurity;
    }

    public String getEncryptionSecurity() {
        return this.encryptionSecurity;
    }

    public void setEncryptionSecurity(String encryptionSecurity) {
        this.encryptionSecurity = encryptionSecurity;
    }

    public String verifyToken(String token) {
        try {
            Key signKey = JoseKit.generateAesKey(this.signSecurity);
            Key encryptionKey = JoseKit.generateOctetJwk(this.encryptionSecurity);
            String playload = JoseKit.verifyJwtSignature(signKey, token);
            String playloadRaw = JoseKit.verifyJwtEncrytion(encryptionKey, playload);
            if (StrUtil.isNotBlank(playloadRaw)) {
                return playloadRaw;
            }
        } catch (Exception e) {
            throw new RuntimeException("Token \u9A8C\u8BC1\u5F02\u5E38");
        }
        return null;
    }
}
