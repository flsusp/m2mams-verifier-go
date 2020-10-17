package main

import (
	"github.com/flsusp/m2mams-verifier-go/m2mams/kprovider"
	"github.com/flsusp/m2mams-verifier-go/m2mams/verifier"
	"github.com/urfave/cli/v2"
	"os"
)

func main() {
	var keyProvider string
	var context string

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "kprovider",
				Aliases:     []string{"kp"},
				Value:       "file",
				Usage:       "from where retrieve the verifying keys (file | env)",
				Destination: &keyProvider,
			},
			&cli.StringFlag{
				Name:        "context",
				Aliases:     []string{"ctx"},
				Usage:       "context information which meaning depends on the chosen kprovider",
				Destination: &context,
			},
		},
		Action: func(c *cli.Context) error {
			tk := c.Args().Get(0)

			var kp kprovider.KeyProvider
			if keyProvider == "file" {
				kp = kprovider.NewLocalFileSystemKProvider(context)
			} else {
				return cli.Exit("Invalid --kprovider value", 1)
			}

			v := verifier.Verifier{
				KeyProvider: kp,
			}

			err := v.VerifySignedToken(tk)
			panicOnError(err)

			return nil
		},
		Name:      "M2MAMS Verifier",
		Usage:     "CLI that can be used to verify signed JWT tokens",
		Version:   "1.0.0",
		UsageText: "m2mams_verifier [--kprovider file|env] [--context <context>] <token>",
		Description: "Verifies a JWT signed token getting the keys from the given `--kprovider`.\n\n" +
			"   If the `--kprovider file` is defined we expect the `--context context` to indicate the path from where " +
			"the public keys are going to be loaded.\n\n" +
			"   If the `--kprovider git` is defined we expect the `--context context` to indicate the git url of the " +
			"repository from where the public keys are going to be loaded. To authenticate on the git repository we " +
			"rely on SSH authentication.\n\n" +
			"   For generating key pairs please check the docs at https://github.com/flsusp/m2mams.",
	}

	err := app.Run(os.Args)
	panicOnError(err)
}

func panicOnError(err error) {
	if err != nil {
		panic(err.Error())
	}
}
