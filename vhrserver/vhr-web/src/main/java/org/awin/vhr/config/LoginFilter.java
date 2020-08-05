package org.awin.vhr.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.awin.vhr.model.Hr;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    @Autowired
    SessionRegistry sessionRegistry;

    /**
     * 尝试身份校验
     *
     * @return
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (!request.getMethod().equals("POST")) {
            //不支持身份验证方法
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod()
            );
        }
        //验证码
        String verify_code = (String) request.getSession().getAttribute("verify_code");
        if (request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)
                || request.getContentType().contains(MediaType.APPLICATION_JSON_UTF8_VALUE)) {
            Map<String, String> loginData = new HashMap<>();
            try {
                loginData = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            } catch (IOException e) {
            } finally {
                String code = loginData.get("code");
                checkCode(response, code, verify_code);
            }
            String userName = loginData.get(getUsernameParameter());
            String passWord = loginData.get(getPasswordParameter());
            if (userName != null) {
                userName = "";
            }
            if (passWord != null) {
                passWord = "";
            }
            assert userName != null;
            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(userName.trim(), passWord);

            //设置详细信息
            setDetails(request, authRequest);
            Hr principal = new Hr();
            principal.setUsername(userName);
            sessionRegistry.registerNewSession(request.getSession(true).getId(), principal);
            return this.getAuthenticationManager().authenticate(authRequest);
        } else {
            checkCode(response, request.getParameter("code"), verify_code);
            return super.attemptAuthentication(request, response);
        }
    }

    public void checkCode(HttpServletResponse resp, String code, String verifyCode) {
        if (code == null || verifyCode == null || "".equals(code)
                || !verifyCode.toLowerCase().equals(code.toLowerCase())) {
            //验证码不正确
            throw new AuthenticationServiceException("验证码不正确！");
        }
    }
}
