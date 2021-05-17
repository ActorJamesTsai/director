package com.avenger.director.app.kit;

import cn.hutool.core.codec.Base64Decoder;
import cn.hutool.core.codec.Base64Encoder;
import cn.hutool.core.util.StrUtil;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;

/**
 * Description:
 *
 * Date: 2021/5/16
 *
 * @author JiaDu
 * @version 1.0.0
 */
public class JoseKit {

    public static Key generateAesKey(String secret) {
        return new AesKey(secret.getBytes(StandardCharsets.UTF_8));
    }

    public static Key generateOctetJwk(String secret) {
        Map<String, Object> keyParam = new HashMap<>();
        keyParam.put("kty", "oct");
        keyParam.put("k", secret);
        try {
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyParam);
            return jwk.getKey();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public static String createJwsHMACSha512(Key signKey, byte[] value) {
        return createJws(signKey, value, "HS512");
    }

    public static String createJws(Key signKey, byte[] value, String algHeaderValue) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            String playload = StrUtil.str(Base64Encoder.encode(value, false), "US-ASCII");
            jws.setEncodedPayload(playload);
            jws.setAlgorithmHeaderValue(algHeaderValue);
            jws.setKey(signKey);
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public static String createJweDirectAes128Sha256(Key encryptionKey, Serializable value) {
        return createJwe(encryptionKey, value, "dir", "A128CBC-HS256");
    }

    public static String createJwe(Key encryptionKey, Serializable value, String algHeaderValue,
        String contentEncryptionAlgorithm) {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setPayload(value.toString());
            jwe.enableDefaultCompression();
            jwe.setAlgorithmHeaderValue(algHeaderValue);
            jwe.setEncryptionMethodHeaderParameter(contentEncryptionAlgorithm);
            jwe.setKey(encryptionKey);
            return jwe.getCompactSerialization();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public static String verifyJwtSignature(Key signKey, String token) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(token);
            jws.setKey(signKey);
            boolean isPass = jws.verifySignature();
            if (isPass) {
                String playload = jws.getEncodedPayload();
                byte[] playloadDecode = Base64Decoder.decode(playload);
                String playloadText = new String(playloadDecode, StandardCharsets.UTF_8);
                return playloadText;
            }
            return null;
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public static String verifyJwtEncrytion(Key encrytionKey, String token) {
        try {
            JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
            jsonWebEncryption.setKey(encrytionKey);
            jsonWebEncryption.setCompactSerialization(token);
            String playload = jsonWebEncryption.getPayload();
            return playload;
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }
}
