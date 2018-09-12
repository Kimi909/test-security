/**
 * 
 */
package com.imooc.security.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imooc.security.core.properties.LoginResponseType;
import com.imooc.security.core.properties.SecurityProperties;

/**
 * @author zhailiang
 * 认证成功后做的处理
 */
@Component("imoocAuthenticationSuccessHandler")
public class ImoocAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired
	private AuthorizationServerTokenServices authorizationServerTokenServices;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

            logger.info("登录成功");

		//获取请求头里Authorization信息
		String header = request.getHeader("Authorization");

		//没有client信息
		if(header == null || !header.startsWith("Basic")){
			throw new UnapprovedClientAuthenticationException("请求头中无client信息");
		}

		/**
		 * 构造OAuth2Request 第一步，从请求头获取clientId
		 */
		//base64解码获取clientId、clientSecret
		String[] tokens = extractAndDecodeHeader(header, request);
		assert tokens.length == 2;

		String clientId = tokens[0];
		String clientSecret  = tokens[1];
		/**
		 * 构造OAuth2Request 第二步，根据clientId 获取ClientDetails对象
		 */
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		if(clientDetails == null ){
			throw new UnapprovedClientAuthenticationException("clientId对应的配置信息不存在，clientId:"+clientId);
		}else if(!StringUtils.equals(clientDetails.getClientSecret(), clientSecret)){
			throw new UnapprovedClientAuthenticationException("clientSecret不匹配，clientId:"+clientId);
		}

		/**
		 * 构造OAuth2Request 第三步，new TokenRequest
		 * 第一个参数是个map，放的是每个授权模式特有的参数，springsecurity会根据这些参数构建Authentication
		 * 我们这里已获取到了Authentication，弄个空的map就可
		 */
		TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(), "custom");
		/**
		 * 构造OAuth2Request 第四步，创建 OAuth2Request
		 */
		OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);
		/**
		 * 构造OAuth2Request 第五步，创建 OAuth2Authentication
		 */
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);
		/**
		 * 构造OAuth2Request 第六步，authorizationServerTokenServices创建 OAuth2AccessToken
		 */
		OAuth2AccessToken accessToken =   authorizationServerTokenServices.createAccessToken(oAuth2Authentication);

		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(accessToken));


	}

	private String[] extractAndDecodeHeader(String header, HttpServletRequest request) throws IOException {

		byte[] base64Token = header.substring(6).getBytes("UTF-8");
		byte[] decoded;
		try {
			decoded = Base64.decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token = new String(decoded, "UTF-8");

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		return new String[] { token.substring(0, delim), token.substring(delim + 1) };
	}

}
