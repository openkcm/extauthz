package policies

// CheckOption is used to pass different values to check function.
type CheckOption func(Engine) error

type Engine interface {
	Check(opts ...CheckOption) (bool, string, error)
}
