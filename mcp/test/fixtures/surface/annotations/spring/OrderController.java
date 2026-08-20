// Spring MVC controller in the style spring.io's own guides use.
//
// Written by the auditor of `configs/semgrep/routes.yml`, not by the author of
// the rules it exercises. Measured against the pack as shipped, only a lone
// string literal matched: the named-argument forms (`value = `, `path = `) and
// the bare annotations reported nothing, and four of an eight-mapping
// controller's misses carried `produces` / `consumes` / `method` — i.e.
// exactly what a production controller writes.
//
// SYSTEMATIC BY DESIGN. Each of the six mapping annotations appears in all
// four forms Spring accepts:
//
//   @XMapping("/p")                positional  (the only one that ever worked)
//   @XMapping(value = "/p", …)     named `value`
//   @XMapping(path = "/p", …)      named `path`
//   @XMapping                      bare, path inherited from the class
//
// That is not thoroughness for its own sake: every one of those is a separate
// pattern alternative in routes.yml, and an alternative no fixture exercises
// is a clause nobody can tell is dead. Deleting any single alternative from
// the pack must turn exactly one row of the expected set red.
//
// `reordered()` is the one that decides the design: with `produces` written
// FIRST, any recovery that reads "the first argument of the span" reads
// `produces = "application/json"`. Measured with the focus removed from the
// PUT rule, that is exactly what this method reports —
// `spring PUT produces = "application/json" [partial]` — while a Semgrep that
// still emits metavariables reports `/reordered`. The extractor refuses the
// text as a path (spaces, quotes), so nothing is fabricated; what is lost is
// the path, on one Semgrep version only. `focus-metavariable: $PATH` makes
// the reported span the literal Semgrep bound BY NAME, so the answer stops
// depending on which Semgrep the reader has.

package com.example.orders;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    // ---- GET ----
    @GetMapping("/get-positional")
    public List<String> getPositional() { return List.of(); }

    @GetMapping(value = "/get-value", produces = "application/json")
    public Map<String, String> getValue() { return Map.of(); }

    @GetMapping(path = "/get-path")
    public String getPath() { return "x"; }

    @GetMapping
    public List<String> getBare() { return List.of(); }

    // ---- POST ----
    @PostMapping("/post-positional")
    public String postPositional() { return "x"; }

    @PostMapping(value = "/post-value", consumes = "application/json")
    public String postValue() { return "x"; }

    @PostMapping(path = "/post-path")
    public String postPath() { return "x"; }

    // Bare, under an unrelated annotation — the span starts at @Deprecated.
    @Deprecated
    @PostMapping
    public String postBare() { return "x"; }

    // ---- PUT ----
    @PutMapping("/put-positional")
    public void putPositional() {}

    // Named arguments in the order that makes first-argument recovery invent
    // `application/json` as a path. See the file header.
    @PutMapping(produces = "application/json", value = "/reordered")
    public void reordered() {}

    @PutMapping(path = "/put-path")
    public void putPath() {}

    @PutMapping
    public void putBare() {}

    // ---- PATCH ----
    @PatchMapping("/{id}/status")
    public void patchPositional(@PathVariable String id) {}

    @PatchMapping(value = "/patch-value")
    public void patchValue() {}

    @PatchMapping(path = "/patch-path")
    public void patchPath() {}

    @PatchMapping
    public void patchBare() {}

    // ---- DELETE ----
    @DeleteMapping("/delete-positional")
    public void deletePositional() {}

    // An array of paths. Not a single literal, so it stays partial with the
    // raw source text visible — never one of the two paths picked at random.
    @DeleteMapping(value = {"/a", "/b"})
    public void deleteValueArray() {}

    @DeleteMapping(path = "/delete-path")
    public void deletePath() {}

    // Bare with empty parens — the same pattern, to Semgrep.
    @DeleteMapping()
    public void deleteBare() {}

    // ---- @RequestMapping: verb-less, so every one of these is ANY ----
    @RequestMapping("/request-positional")
    public String requestPositional() { return "x"; }

    // The verb lives in an attribute this pack does not read. ANY is the
    // truth; guessing GET from it would be an invention.
    @RequestMapping(value = "/request-value", method = RequestMethod.GET)
    public String requestValue() { return "x"; }

    @RequestMapping(path = "/request-path")
    public String requestPath() { return "x"; }

    @RequestMapping
    public String requestBare() { return "x"; }
}
