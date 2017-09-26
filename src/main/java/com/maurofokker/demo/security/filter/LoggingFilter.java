package com.maurofokker.demo.security.filter;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Optional;

/**
 * Created by mauro on 9/25/17.
 * Logging filter that will be added to chain filter in security config
 */
@Component
public class LoggingFilter extends GenericFilterBean {
    private final Logger log = Logger.getLogger(LoggingFilter.class);

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        final String url = httpServletRequest.getRequestURL().toString();
        final String queryString = Optional.ofNullable(httpServletRequest.getQueryString()).map(value -> "?" + value).orElse("");
        log.info(String.format("applying LoggingFilter for URI: %s%s", url, queryString));

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
