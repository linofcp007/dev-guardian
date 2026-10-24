// Does not type-check: gosec's SSA and taint rules skip this package.
package broken

func F() int { return undefinedThing }
