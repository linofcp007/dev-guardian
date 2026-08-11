package com.example.orders;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/spring/orders")
public class OrderController {

    @GetMapping("/list")
    public List<String> list() {
        return List.of();
    }

    @PostMapping("/create")
    public String create(@RequestBody String body) {
        return body;
    }

    @PutMapping("/{id}")
    public String replace(@PathVariable String id, @RequestBody String body) {
        return id + body;
    }

    @PatchMapping("/{id}/status")
    public String status(@PathVariable String id) {
        return id;
    }

    @DeleteMapping("/{id}")
    public void remove(@PathVariable String id) {
    }

    // Verb-less: @RequestMapping carries its method in a separate attribute we
    // do not read, so the route is reported as ANY rather than guessed.
    @RequestMapping("/legacy")
    public String legacy() {
        return "legacy";
    }
}
