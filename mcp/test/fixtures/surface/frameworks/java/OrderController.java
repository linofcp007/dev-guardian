package com.example;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.*;
import static java.util.Collections.emptyList;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    // J01 control: single string argument
    @GetMapping("/list")
    public List<String> list() { return emptyList(); }

    // J02 named-argument form — very common in real Spring
    @GetMapping(value = "/detail", produces = "application/json")
    public Map<String, String> detail() { return Map.of(); }

    // J03 bare annotation, path inherited from the class @RequestMapping
    @GetMapping
    public List<String> all() { return emptyList(); }

    // J04 path attribute name instead of value
    @PostMapping(path = "/create")
    public String create() { return "x"; }

    // J05 array of paths
    @DeleteMapping({"/a", "/b"})
    public void del() {}

    // J06 @RequestMapping with method attribute
    @RequestMapping(value = "/legacy", method = RequestMethod.GET)
    public String legacy() { return "l"; }

    // J07 PutMapping/PatchMapping single arg (control)
    @PutMapping("/{id}")
    public void put(@PathVariable String id) {}

    @PatchMapping("/{id}/status")
    public void patch(@PathVariable String id) {}
}
