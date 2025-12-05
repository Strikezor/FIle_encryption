package com.tcs.bancs.microservices.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private RateLimitInterceptor rateLimitInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Apply to specific URL patterns
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/EncFile/**") // Apply to all endpoints in your EncFile controller
                // .addPathPatterns("/OtherController/**") // Add more here easily
                .excludePathPatterns("/EncFile/public-endpoint"); // Exclude specific ones if needed
    }
}
