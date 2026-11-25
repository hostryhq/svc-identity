package main

import (
	"net/http"

	"github.com/hostryhq/svc-identity/internal/devtools"
)

// devAids are the development-only capture and clock (see package devtools); both are nil unless
// their flags are set, and loadConfig has already refused the flags outside dev, test and ci.
type devAids struct {
	capture *devtools.Capture
	clock   *devtools.Clock
}

func (c *config) devAids() *devAids {
	a := &devAids{}
	if c.DevCapture {
		a.capture = &devtools.Capture{}
	}
	if c.DevClock {
		a.clock = &devtools.Clock{}
	}
	return a
}

// handler wraps the service handler with the /dev/ routes when any aid is on. The guard is checked
// again here, so a handler is never built for a non-development configuration.
func (a *devAids) handler(c *config, api http.Handler) (http.Handler, error) {
	if a.capture == nil && a.clock == nil {
		return api, nil
	}
	dev, err := devtools.Handler(c.Environment, c.AllowTestSMS, a.capture, a.clock)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/dev/", dev)
	mux.Handle("/", api)
	return mux, nil
}
