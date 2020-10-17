package kprovider

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validPublicKey = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2KlYfdkddYcP8rMdgtGb\nQiudb35oorWCR1kINoXhuurDlNIv+v5k1x/kcsKYO4kjbN6f1ohUqkzvfYEApvwS\nRQfM5N4Cy1ZtweyB5s2HsZclmy/fx2UKTp/PgeeO8lQX96WIFIlSMqKC/8Oo95nK\nzXTNQpWbO6/rskjW1X+l8HOQP7+DdFyVVRaP+yfVbJhjvUPDkyPcfqouAtKqHPDi\n+0SJF0apyLM+WbFWFFTrRO4Ne+jgxotZj6SfdoSuJyBRbJ30DmbLRWFDj9lZQoju\nUGENuy1zc31T9wHU+/Thz8gMwJwoDYkr8iMMCBPuDVObJRiodhXdawkgZKHOPlV+\nRaTpu0aiWf7ksxXelyiS5csz9Z+LD/0YQs0r/dtzJfcxGCY0/ixkhptDBb5zZFpk\nOlc3vkoQxYudBy5fwSxkTyZxNPYtELpoyEgn5RA5XLe1YRPju9G3jy/rWJhLaDMT\nmsOSNUk5OtEQ66beC0oS5ZUHwzOLLXhSVeStx+qIBIdVuqdrdkNDOOphgyETEJ2x\nkeTnmkGkCx4E2IP/iB9376RClcrKzyXjJxxHmansSNydOO1x0cORCN1W2zfIpRrb\nj1SUay+kmBRHtsiZuFWsyLdFTXd96swcNSLc9x8X4X2OaprBP2f8Hc9r32yISlur\nohy9FMF7UqdECHQA5GwEziMCAwEAAQ==\n-----END PUBLIC KEY-----\n"

func TestLoadKeyFromFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemKProvider{
		FileSystem: fs,
		Path: "/tmp",
	}

	fs.MkdirAll("/tmp/your_email@example.com", 0755)
	afero.WriteFile(fs, "/tmp/your_email@example.com/test.pub.pem", []byte(validPublicKey), 0644)

	_, err := pkp.LoadPublicKey("your_email@example.com", "test")
	assert.NoError(t, err)
}

func TestLoadKeyFailsOnMissingFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	pkp := LocalFileSystemKProvider{
		FileSystem: fs,
		Path: "/tmp",
	}

	_, err := pkp.LoadPublicKey("your_email@example.com", "test")
	assert.Error(t, err)
}
