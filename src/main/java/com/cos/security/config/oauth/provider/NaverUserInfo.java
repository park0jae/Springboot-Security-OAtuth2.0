package com.cos.security.config.oauth.provider;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo {

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    private Map<String, Object> attributes;
    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }
    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getName() {
        return attributes.get("name").toString();
    }

    @Override
    public String getEmail() {
        return attributes.get("email").toString();
    }
}