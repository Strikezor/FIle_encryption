package com.tcs.bancs.microservices.configuration;

import com.google.gson.Gson;
import com.tcs.bancs.microservices.response.ADESH_ENC_FILE_RETURN; // Your existing response class
import com.tcs.bancs.microservices.services.RateLimiterService;
import io.github.bucket4j.Bucket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    @Autowired
    private RateLimiterService rateLimiterService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        
        String apiKey = request.getRemoteAddr(); // Or "X-Forwarded-For" header
        if (apiKey == null || apiKey.isEmpty()) {
            apiKey = "unknown-client";
        }

        Bucket tokenBucket = rateLimiterService.resolveBucket(apiKey);
        
        // Try to consume 1 token
        if (tokenBucket.tryConsume(1)) {
            return true; // Request allowed, proceed to Controller
        } else {
            // Rate limit exceeded - Return JSON error
            returnErrorResponse(response);
            return false; // Block request
        }
    }

    private void returnErrorResponse(HttpServletResponse response) throws Exception {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");

        // Construct your standard error object
        ADESH_ENC_FILE_RETURN result = new ADESH_ENC_FILE_RETURN();
        result.setERROR_CODE("ER429");
        result.setERROR_DESCRIPTION("Rate limit exceeded. Please try again later.");
        result.setRESPONSE_STATUS("1");

        // Write JSON to output
        String json = new Gson().toJson(result);
        response.getWriter().write(json);
    }
}
