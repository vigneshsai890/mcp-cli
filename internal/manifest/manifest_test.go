package manifest

import "testing"

func TestDecodeValidManifest(t *testing.T) {
	data := []byte(`{"schemaVersion":1,"name":"safe-tool","version":"1.0.0","runtime":{"kind":"npm","command":"node","args":["server.js"]},"env":{"API_TOKEN":"HOST_API_TOKEN"}}`)
	m, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "safe-tool" || m.Env["API_TOKEN"] != "HOST_API_TOKEN" {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestDecodeRejectsUnknownTrailingAndValues(t *testing.T) {
	bad := []string{
		`{"schemaVersion":1,"name":"safe","version":"1","runtime":{"kind":"exec","command":"tool"},"extra":true}`,
		`{"schemaVersion":1,"name":"safe","version":"1","runtime":{"kind":"exec","command":"tool"}} {}`,
		`{"schemaVersion":1,"name":"../bad","version":"1","runtime":{"kind":"exec","command":"tool"}}`,
		`{"schemaVersion":1,"name":"safe","version":"1","runtime":{"kind":"shell","command":"sh"}}`,
		`{"schemaVersion":1,"name":"safe","version":"1","runtime":{"kind":"exec","command":"tool"},"env":{"TOKEN":"literal-secret!"}}`,
	}
	for _, input := range bad {
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("Decode(%s) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeRejectsLoaderAndRuntimeControlEnvironment(t *testing.T) {
	for _, env := range []string{
		`"LD_PRELOAD":"HOST_VALUE"`,
		`"TOKEN":"DYLD_INSERT_LIBRARIES"`,
		`"NODE_OPTIONS":"HOST_VALUE"`,
		`"PERLLIB":"HOST_VALUE"`,
		`"TOKEN":"PERLLIB"`,
		`"PATH":"HOST_VALUE"`,
		`"TOKEN":"PYTHONPATH"`,
		`"MCP_ALLOW_UNSANDBOXED_CARGO":"HOST_VALUE"`,
	} {
		input := `{"schemaVersion":1,"name":"safe","version":"1","runtime":{"kind":"exec","command":"tool"},"env":{` + env + `}}`
		if _, err := Decode([]byte(input)); err == nil {
			t.Errorf("Decode unexpectedly accepted control environment mapping %s", env)
		}
	}
}
