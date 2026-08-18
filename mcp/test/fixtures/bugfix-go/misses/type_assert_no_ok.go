package misses

func maybeString(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func switchPlain(v interface{}) string {
	switch v.(type) {
	case string:
		return "s"
	}
	return ""
}

func switchBound(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	}
	return ""
}
