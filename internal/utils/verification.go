package utils

import (
	"reflect"
)

// CheckAllPopulated returns false if at least one value in the slice is nil or zero.
func CheckAllPopulated(values ...any) bool {
	for _, v := range values {
		if isZero(v) {
			return false
		}
	}
	return true
}

// isZero checks whether v is nil or the zero value of its type.
func isZero(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func:
		return rv.IsNil()
	default:
		return rv.IsZero()
	}
}
