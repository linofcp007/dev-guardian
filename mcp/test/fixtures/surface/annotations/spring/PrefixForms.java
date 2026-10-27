// Spring class-level prefixes: every shape the join in
// `mcp/src/surface/resolvers/classPrefix.ts` decides, one class each.
//
// A route here is RESOLVED only when its class is a concrete @RestController /
// @Controller with one literal @RequestMapping, or with none and no supertype
// that could carry one. Everything else stays partial at the path the method
// names — never joined to a prefix that may not be the one Spring serves it
// under. Each class below is also the fixture of one alternative or guard of
// the `guardian-scope-spring-*` rules, so the ablation harness can tell it
// is live.

package com.example.prefixes;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

// The named `value =` form, beside `produces`: /v1/items/list, and the bare
// mapping is served AT the prefix.
@RestController
@RequestMapping(value = "/v1/items", produces = "application/json")
class ValuePrefixController {
    @GetMapping("/list")
    public String list() { return "[]"; }

    @PostMapping
    public String create() { return "{}"; }
}

// The named `path =` form, both halves relative, on a plain @Controller:
// Spring prepends the slash to each, so /v2/items/detail.
@Controller
@RequestMapping(path = "v2/items")
class PathPrefixController {
    @GetMapping("detail")
    public String detail() { return "d"; }
}

// A constant prefix: its value is not in this file. Partial at `/c`.
@RestController
@RequestMapping(Paths.ORDERS)
class ConstantPrefixController {
    @GetMapping("/c")
    public String c() { return "c"; }
}

// A prefix and no method mapping: no endpoint at all. 3.6.1 reported the
// class-level annotation as `ANY /only`, a route Spring never serves.
@RestController
@RequestMapping("/only")
class OnlyPrefixController {
    public String helper() { return "h"; }
}

// No prefix, no supertype: served at the path the method names.
// @RestController("beanName") is the same handler as the bare annotation.
@RestController("healthBean")
class NoPrefixController {
    @GetMapping("/health")
    public String health() { return "ok"; }
}

// No prefix, but a superclass that may carry one: partial.
@RestController
class InheritingController extends BaseController {
    @GetMapping("/inherited")
    public String inherited() { return "i"; }
}

// No prefix, and an interface that DOES carry one — the OpenAPI-generator
// shape: served at /feign/impl, which only the interface says. Partial.
@RestController
class ImplementingController implements OrdersApi {
    @DeleteMapping("/impl")
    public void impl() {}
}

// An abstract handler is no bean: its mappings are served under whichever
// subclass inherits them, at that subclass's prefix if it declares one.
// Partial, even with a literal prefix of its own.
@RestController
@RequestMapping("/abstract")
abstract class AbstractController {
    @GetMapping("/a")
    public String a() { return "a"; }
}

// An API interface: its type-level @RequestMapping is no route, and its
// abstract methods' mappings stay partial — the implementing controller's
// own prefix, if it has one, wins. One abstract method per argument form.
@RequestMapping("/feign")
interface OrdersApi {
    @RequestMapping("/abs-positional")
    String absPositional();

    @RequestMapping(value = "/abs-value")
    String absValue();

    @RequestMapping(path = "/abs-path")
    String absPath();
}

// Nesting: each route belongs to the innermost type around it.
// @RequestMapping("/commented") — a comment, never a prefix.
@RestController
@RequestMapping("/outer")
public class OuterController {
    @GetMapping("/o")
    public String o() { return "o"; }

    // Not a handler: partial, and never /outer/helper.
    static class Helper {
        @GetMapping("/helper")
        public String helper() { return "h"; }
    }

    // A handler of its own, with its own prefix: /nested/n.
    @RestController
    @RequestMapping("/nested")
    static class NestedController {
        @GetMapping("/n")
        public String n() { return "n"; }
    }

    // An interface and a record are boundaries too.
    interface InnerApi {
        @GetMapping("/inner-iface")
        String innerIface();
    }

    record Dto(String v) {
        @GetMapping("/in-record")
        public String inRecord() { return v; }
    }
}

// A plain @Controller with a superclass and no prefix: partial, like the
// @RestController one above — the fixture of the inherits rule's
// `@Controller` branch, which read DEAD without it.
@Controller
class LegacyPageController extends BasePage {
    @GetMapping("/page")
    public String page() { return "page"; }
}
