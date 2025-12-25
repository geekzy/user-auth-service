package com.example.userauthentication.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Root controller for handling base URL redirects.
 */
@Controller
public class RootController {

    /**
     * Redirect root URL to login page.
     */
    @GetMapping("/")
    public String root() {
        return "redirect:/auth/login";
    }
}