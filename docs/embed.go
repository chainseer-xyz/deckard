// Package docs embeds the hand-written OpenAPI specification so the API can
// serve it at /api/v1/openapi.yaml.
package docs

import _ "embed"

// OpenAPI is the OpenAPI 3 document describing deckard's HTTP API.
//
//go:embed openapi.yaml
var OpenAPI []byte
