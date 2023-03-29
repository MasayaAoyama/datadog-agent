package apiserver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestLifecycle(t *testing.T) {
	fxutil.Test(t, fx.Options(Module, log.MockModule), func(Component) {
		res, err := http.Get("http://localhost:6162/config")
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
}
