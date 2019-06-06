package com.wzy.cas.myauth;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

import javax.security.auth.login.AccountNotFoundException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

/**
* @Description:    自定义验证器
* @Author:         Wen
* @CreateDate:     2019/6/6 12:58
* @UpdateUser:     Wen
* @UpdateDate:     2019/6/6 12:58
* @UpdateRemark:   修改内容
* @Version:        1.0
*/
public class MyAuthenticationHandler  extends AbstractUsernamePasswordAuthenticationHandler {

    /*
       在cas的认证过程中逐个执行authenticationHandlers中配置的认证管理，直到有一个成功为止,
       所以我们在使用自定义验证器的时候,查询数据库操作,要自己实现,而不能使用cas自带的，包括密码加密等。
     */
    public MyAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException {

        if("admin".equals(credential.getUsername())){
            return createHandlerResult(credential,
                    this.principalFactory.createPrincipal(credential.getUsername()),
                    new ArrayList<>(0));
        }else{
            throw new AccountNotFoundException("必须是admin用户才允许通过");
        }
    }

}
