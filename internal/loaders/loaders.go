package loaders

import "fmt"

type Loaders struct {
	Available map[string]Loader
}

var (
	AvailableLoaders = &Loaders{
		Available: map[string]Loader{},
	}
)

func (l *Loaders) List() []string {
	var ldrs []string
	for ldr := range l.Available {
		ldrs = append(ldrs, ldr)
	}

	return ldrs
}

func (l *Loaders) Register(name string, ldr Loader) {
	if ldr.IsInjector() {
		ldr.AddValidArgs([]string{"target", "pid", "args"})
	}

	l.Available[name] = ldr
}

func (l *Loaders) Get(name string) (Loader, error) {

	if ldr, ok := l.Available[name]; ok {
		return ldr, nil
	}

	return nil, fmt.Errorf("unknown loader")
}
