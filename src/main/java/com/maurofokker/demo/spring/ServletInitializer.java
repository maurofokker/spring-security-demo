package com.maurofokker.demo.spring;

import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

public class ServletInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {       
        return null;
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class[] {  BasicSecurityConfig.class, DemoWebConfig.class };
    }

    @Override
    protected String[] getServletMappings() {
        return new String[] { "/" };
    }

}
