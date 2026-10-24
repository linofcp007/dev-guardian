// Does not type-check: govulncheck cannot analyse this module.
package broken

func F() int { return undefinedThing }
