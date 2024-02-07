package config

import (
	_ "embed"
	"regexp"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	// Server
	confGRPCPort             = "GRPC_PORT"
	confHTTPPort             = "HTTP_PORT"
	confPromPort             = "PROM_PORT"
	confServerRequestTimeout = "SERVER_REQUEST_TIMEOUT"

	confEnv = "ENV"
)

func init() {
	viper.SetDefault(confHTTPPort, ":8080")
	viper.SetDefault(confGRPCPort, ":8081")
	viper.SetDefault(confPromPort, ":9090")
	viper.SetDefault(confServerRequestTimeout, "180s")
	viper.SetDefault(confEnv, "dev")

}

type Config struct {
	Development bool
	Server      Server
}

func (c Config) Validate() error {
	if err := c.Server.Validate(); err != nil {
		return err
	}
	return nil
}

type Service struct {
	Endpoint string
}

type Server struct {
	GRPCPort       string
	HTTPPort       string
	PromPort       string
	RequestTimeout time.Duration
	Env            string
}

func (s Server) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.HTTPPort, validation.Match(regexp.MustCompile(":.+"))),
		validation.Field(&s.GRPCPort, validation.Match(regexp.MustCompile(":.+"))),
		validation.Field(&s.PromPort, validation.Match(regexp.MustCompile(":.+"))),
		validation.Field(&s.RequestTimeout, validation.Required),
		validation.Field(&s.Env, validation.Required),
	)
}

type StripeService struct {
	Key           string
	WebHookSecret string
}

type DB struct {
	User     string
	Password string
	Host     string
	Port     string
	DBName   string
	SSLMode  string
}

func GetConfig(devMode bool, envFile string) (*Config, error) {
	viper.SetEnvPrefix("APPROVALS")
	viper.AutomaticEnv()

	if envFile != "" {
		if err := godotenv.Load(envFile); err != nil {
			return nil, errors.Wrap(err, "failed to load env file")
		}
	}

	// Parse duration configs
	var (
		requestReadTimeout time.Duration
	)
	var durationVariables = map[string]*time.Duration{
		confServerRequestTimeout: &requestReadTimeout,
	}

	for param, ptr := range durationVariables {
		v := viper.GetDuration(param)
		if v < time.Millisecond {
			return nil, errors.Errorf("invalid duration for %s: %v", param, v)
		}

		*ptr = v
	}

	cfg := Config{
		Development: devMode,
		Server: Server{
			GRPCPort:       viper.GetString(confGRPCPort),
			HTTPPort:       viper.GetString(confHTTPPort),
			PromPort:       viper.GetString(confPromPort),
			RequestTimeout: requestReadTimeout,
			Env:            viper.GetString(confEnv),
		},
	}

	return &cfg, cfg.Validate()
}
