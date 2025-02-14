package main

import (
	"github.com/ma111e/moonboots/cmd/moonboots"
	"github.com/ma111e/moonboots/internal/consts"
	"github.com/mattn/go-colorable"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func init() {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())

	viper.SetEnvPrefix(consts.EnvPrefix)
}

func main() {
	if err := moonboots.RootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}
