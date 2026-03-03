package utils

func Ptr[T any](value T) *T {
	var ret = value
	return &ret
}
