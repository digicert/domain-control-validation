package com.digicert.validation.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class LoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // start time
        String transactionId = UUID.randomUUID().toString();
        log.info("Starting request processing uri={} method={} transaction_id={}", request.getRequestURI(), request.getMethod(), transactionId);
        long startTime = System.currentTimeMillis();

        filterChain.doFilter(request, response);

        log.info("Request Complete elapsed={} status={} transaction_id={}", System.currentTimeMillis() - startTime, response.getStatus(), transactionId);
    }
}