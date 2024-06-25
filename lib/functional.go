package lib

type ReduceCb[T, R any] func(acc R, current T) R

func Reduce[T any, R any](s []T, fn ReduceCb[T, R], initialValue R) R {
	partial := initialValue
	for _, el := range s {
		partial = fn(partial, el)
	}

	return partial
}

func Accumulate[T any](s []T, fn ReduceCb[T, T]) (T, error) {
	var partial T
	if len(s) == 0 {
		return partial, Error{Msg: "Empty slice"}
	}
	partial = (s)[0]
	for i, el := range s {
		if i == 0 {
			continue
		}
		partial = fn(partial, el)
	}

	return partial, nil
}

func Map[T any, R any](s []T, fn func(T) R) []R {
	mapped := make([]R, len(s))
	for index, el := range s {
		mapped[index] = fn(el)
	}

	return mapped
}

func IndexedMap[T any, R any](s []T, fn func(int, T) R) []R {
	mapped := make([]R, len(s))
	for i, el := range s {
		mapped[i] = fn(i, el)
	}

	return mapped
}

func Filter[T any](s []T, fn func(T) bool) []T {
	var filtered []T
	for _, el := range s {
		if fn(el) {
			filtered = append(filtered, el)
		}
	}

	return filtered
}

func IndexedFilter[T any](s []T, fn func(int, T) bool) []T {
	var filtered []T
	for i, el := range s {
		if fn(i, el) {
			filtered = append(filtered, el)
		}
	}

	return filtered
}

func Keys[K comparable, V any](m map[K]V) []K {
	var keys []K
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func Exists[T any](s []T, fn func(T) bool) bool {
	for _, el := range s {
		if fn(el) {
			return true
		}
	}

	return false
}

func Find[T any](s []T, fn func(T) bool) *T {
	for _, el := range s {
		if fn(el) {
			return &el
		}
	}

	return nil
}

func GroupBy[T any, S comparable](s []T, fn func(T) S) map[S][]T {
	grouped := make(map[S][]T)
	for _, el := range s {
		key := fn(el)
		grouped[key] = append(grouped[key], el)
	}

	return grouped
}

func GroupByPointer[T any, S comparable](s []T, fn func(T) S) map[S][]*T {
	grouped := make(map[S][]*T)
	for _, el := range s {
		key := fn(el)
		grouped[key] = append(grouped[key], &el)
	}

	return grouped
}

func Reverse[T any](s []T) []T {
	reversed := make([]T, len(s))
	for i, el := range s {
		reversed[len(s)-1-i] = el
	}

	return reversed
}

func Zip[T any, S any](t []T, s []S) []Pair[T, S] {
	var zipped []Pair[T, S]
	for i, el := range t {
		zipped = append(zipped, Pair[T, S]{First: el, Second: s[i]})
	}

	return zipped
}

// Associate associates two slices by a predicate function.
// The order of the final map is the order of the first slice.
func Associate[T comparable, S any](t []T, s []S, fn func(T, S) bool) map[T]S {
	associated := make(map[T]S)
	for i, tEl := range t {
		match := Find(s, func(sEl S) bool {
			return fn(tEl, sEl)
		})

		if match != nil {
			associated[tEl] = s[i]
		}
	}

	return associated
}

func Values[K comparable, V any](m map[K]V) []V {
	var values []V
	for _, v := range m {
		values = append(values, v)
	}

	return values
}

func Contains[T comparable](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func PointerContains[T comparable](s []*T, e T) bool {
	for _, a := range s {
		if *a == e {
			return true
		}
	}
	return false
}

func ContainsFunc[T any](s []T, f func(T) bool) bool {
	for _, a := range s {
		if f(a) {
			return true
		}
	}
	return false
}
