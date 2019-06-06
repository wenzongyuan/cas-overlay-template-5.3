package com.wzy.cas.myencoder;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.math.BigInteger;
import java.security.MessageDigest;
/**
* @Description:    自定义密码认证
* @Author:         Wen
* @CreateDate:     2019/6/6 12:57
* @UpdateUser:     Wen
* @UpdateDate:     2019/6/6 12:57
* @UpdateRemark:   修改内容
* @Version:        1.0
*/
public class CustomPasswordEncoder implements PasswordEncoder {

    private final Logger logger = LoggerFactory.getLogger(CustomPasswordEncoder.class);

    @Override
    public String encode(CharSequence rawPassword) {
        try {
            //对数据进行md5加密
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(rawPassword.toString().getBytes());
            String pwd = new BigInteger(1, md.digest()).toString(16);
            logger.info("encode方法：加密前（ {} ），加密后（ {} ）",rawPassword,pwd);
            return pwd;
        } catch (Exception e) {
            logger.error("对密码进行md5异常",e);
            return null;
        }
    }

    /**
     * 判断密码是否匹配
     * @param rawPassword
     * @param encodedPassword
     * @return
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 判断密码为空,直接返回false
        if (StringUtils.isBlank(rawPassword)) {
            return false;
        }

        //调用上面的encode 对请求密码进行MD5处理
        String pass = this.encode(rawPassword.toString());

        logger.info("matches方法：请求密码为：{} ，数据库密码为：{}，加密后的请求密码为：{}",rawPassword,encodedPassword,pass);
        //比较密码是否相等
        return pass.equals(encodedPassword);
    }

}
