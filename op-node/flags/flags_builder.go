package flags

import (
	"time"

	"github.com/urfave/cli/v2"
)

var (
	BuilderEnabledFlag = &cli.BoolFlag{
		Name:     "l2.builder.enabled",
		Usage:    "Enable the Builder API client",
		Required: false,
		EnvVars:  prefixEnvVars("L2_BUILDER_ENABLED"),
		Value:    false,
		Category: BuilderCategory,
	}
	BuilderEndpointFlag = &cli.StringFlag{
		Name:     "l2.builder.endpoint",
		Usage:    "Address of Builder API HTTP endpoint to use.",
		Required: false,
		EnvVars:  prefixEnvVars("L2_BUILDER_ENDPOINT"),
		Category: BuilderCategory,
	}
	BuilderRequestTimeoutFlag = &cli.DurationFlag{
		Name:     "l2.builder.timeout",
		Usage:    "Timeout for requests to the Builder API.",
		Required: false,
		EnvVars:  prefixEnvVars("L2_BUILDER_TIMEOUT"),
		Value:    time.Millisecond * 500,
		Category: BuilderCategory,
	}
	BuilderRequestSignerFlag = &cli.StringFlag{
		Name:     "l2.builder.request-signer",
		Usage:    "Private key from proposer in hex format to sign get block payload requests to the builder.",
		Required: false,
		EnvVars:  prefixEnvVars("L2_BUILDER_SIGNER"),
		Category: BuilderCategory,
	}
)

// BuilderFlags returns the builder-related flags
func BuilderFlags() []cli.Flag {
	return []cli.Flag{
		BuilderEnabledFlag,
		BuilderEndpointFlag,
		BuilderRequestTimeoutFlag,
		BuilderRequestSignerFlag,
	}
}
