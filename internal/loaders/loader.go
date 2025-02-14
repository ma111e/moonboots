package loaders

type Loader interface {
	Init()
	Parse(args map[string]string) error
	LoadTarget() error
	Run([]byte) error
	ReportPID() error
	Cleanup() error
	SetError(error)
	ValidArchs() []string

	IsInjector() bool
	AddValidArgs([]string)
}
