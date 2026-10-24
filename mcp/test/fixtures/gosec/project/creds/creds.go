package creds

// A fixture value, not a credential: it trips G101 by its name.
var dbPassword = "fixture-not-a-real-password-0000"

func Password() string { return dbPassword }
