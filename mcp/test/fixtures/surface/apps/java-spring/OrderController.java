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

    // KNOWN LIMITATION, pinned deliberately: the named-argument annotation form
    // is NOT matched, so no route is reported for this method. `@GetMapping
    // ($PATH, ...)` would be the obvious fix and Semgrep rejects it outright as
    // "Invalid pattern for Java". If a future Semgrep starts matching this, the
    // E2E route set below changes and the limitation note in routes.yml and
    // CHANGELOG.md needs deleting — which is exactly why it is pinned here.
    @GetMapping(value = "/named", produces = "application/json")
    public String named() {
        return "named";
    }
}
