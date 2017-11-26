package com.faisco.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {
    @RequestMapping("/index")
    public String index(ModelMap map) {
        map.addAttribute("hello", "hello Thymeleaf!");
        return "index";
    }
}
