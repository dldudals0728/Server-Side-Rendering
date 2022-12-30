package com.SSR.CTSoft.Thymeleaf.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class UserController {
    @GetMapping("test")
    public String test(Model model) {
        model.addAttribute("data", "test data");
        return "/test";
    }
}
