package api_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestContractIsValidOpenAPI(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI document: %v", err)
	}
}

func TestCatalogWorkflowContract(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	repositories := document.Paths.Find("/workspaces/{workspace_id}/repositories")
	if repositories == nil || repositories.Post == nil {
		t.Fatal("create repository operation is missing")
	}
	assertRequiredHeader(t, repositories.Post, "Idempotency-Key")
	assertCapability(t, repositories.Post, "catalog:repositories:create")
	if repositories.Post.Responses.Value("201") == nil {
		t.Error("create repository must return 201")
	}
	if repositories.Post.Responses.Value("409") == nil {
		t.Error("create repository must document idempotency conflict")
	}

	link := document.Paths.Find("/workspaces/{workspace_id}/applications/{application_id}/repositories/{repository_id}")
	if link == nil || link.Put == nil {
		t.Fatal("application repository link operation is missing")
	}
	assertCapability(t, link.Put, "catalog:application-repositories:link")
	if link.Put.Responses.Value("200") == nil {
		t.Error("link replay must return the existing relationship with 200")
	}
	if link.Put.Responses.Value("201") == nil {
		t.Error("a newly created link must return 201")
	}
	if link.Put.Parameters.GetByInAndName("header", "Idempotency-Key") != nil {
		t.Error("link convergence must not require an idempotency header")
	}
}

func TestCreateImportAnalysisContextContract(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	request := document.Components.Schemas["CreateImportRequest"]
	if request == nil || request.Value == nil {
		t.Fatal("CreateImportRequest schema is missing")
	}
	context := request.Value.Properties["analysis_context"]
	if context == nil || context.Value == nil {
		t.Fatal("create import analysis_context is missing")
	}
	for _, name := range request.Value.Required {
		if name == "analysis_context" {
			t.Error("analysis_context must remain optional")
		}
	}

	response := document.Components.Schemas["Import"]
	if response == nil || response.Value == nil ||
		response.Value.Properties["analysis_context"] == nil {
		t.Fatal("Import response must expose accepted analysis_context provenance")
	}

	analysis := document.Components.Schemas["AnalysisContextRequest"]
	if analysis == nil || analysis.Value == nil {
		t.Fatal("AnalysisContextRequest schema is missing")
	}
	kind := analysis.Value.Properties["analysis_kind"]
	if kind == nil || kind.Value == nil || kind.Value.Const != "sast" {
		t.Errorf("analysis_kind const = %#v, want sast", kind)
	}
	target := document.Components.Schemas["AnalysisTarget"]
	if target == nil || target.Value == nil {
		t.Fatal("AnalysisTarget schema is missing")
	}
	targetType := target.Value.Properties["type"]
	if targetType == nil || targetType.Value == nil || targetType.Value.Const != "repository" {
		t.Errorf("analysis target type const = %#v, want repository", targetType)
	}
}

func TestEveryOperationDeclaresCapabilities(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	for path, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			value, ok := operation.Extensions["x-required-capabilities"]
			if !ok {
				t.Errorf("%s %s has no x-required-capabilities", method, path)
				continue
			}
			capabilities, ok := value.([]any)
			if !ok || len(capabilities) == 0 {
				t.Errorf("%s %s has invalid x-required-capabilities: %#v", method, path, value)
			}
		}
	}
}

func TestIngestionWorkflowContract(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	imports := document.Paths.Find("/workspaces/{workspace_id}/imports")
	if imports == nil || imports.Post == nil {
		t.Fatal("create import operation is missing")
	}
	assertRequiredHeader(t, imports.Post, "Idempotency-Key")
	if imports.Post.Responses.Value("201") == nil {
		t.Error("create import must return 201")
	}

	content := document.Paths.Find("/workspaces/{workspace_id}/imports/{import_id}/content")
	if content == nil || content.Put == nil || content.Put.RequestBody == nil {
		t.Fatal("streaming upload operation is missing")
	}
	if content.Put.RequestBody.Value.Content.Get("application/octet-stream") == nil {
		t.Error("upload must accept application/octet-stream")
	}
	if content.Put.Responses.Value("413") == nil {
		t.Error("upload must document size-limit failure")
	}

	complete := document.Paths.Find("/workspaces/{workspace_id}/imports/{import_id}/complete")
	if complete == nil || complete.Post == nil {
		t.Fatal("complete import operation is missing")
	}
	assertRequiredHeader(t, complete.Post, "Idempotency-Key")
	accepted := complete.Post.Responses.Value("202")
	if accepted == nil || accepted.Value == nil {
		t.Fatal("complete import must return 202")
	}
	if accepted.Value.Headers["Location"] == nil {
		t.Error("202 response must provide Location")
	}

	operation := document.Paths.Find("/workspaces/{workspace_id}/operations/{operation_id}")
	if operation == nil || operation.Get == nil {
		t.Fatal("operation status endpoint is missing")
	}
}

func TestErrorsUseProblemDetails(t *testing.T) {
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromFile("openapi.yaml")
	if err != nil {
		t.Fatalf("load OpenAPI document: %v", err)
	}

	for path, item := range document.Paths.Map() {
		for method, operation := range item.Operations() {
			for status, response := range operation.Responses.Map() {
				if status[0] != '4' && status[0] != '5' {
					continue
				}
				if response.Value.Content.Get("application/problem+json") == nil {
					t.Errorf("%s %s response %s is not application/problem+json", method, path, status)
				}
			}
		}
	}
}

func assertRequiredHeader(t *testing.T, operation *openapi3.Operation, name string) {
	t.Helper()
	parameter := operation.Parameters.GetByInAndName("header", name)
	if parameter == nil || !parameter.Required {
		t.Errorf("%s must be a required header", name)
	}
}

func assertCapability(t *testing.T, operation *openapi3.Operation, want string) {
	t.Helper()
	value, ok := operation.Extensions["x-required-capabilities"]
	if !ok {
		t.Fatalf("operation has no x-required-capabilities")
	}
	capabilities, ok := value.([]any)
	if !ok {
		t.Fatalf("x-required-capabilities has unexpected value %#v", value)
	}
	for _, capability := range capabilities {
		if capability == want {
			return
		}
	}
	t.Errorf("x-required-capabilities = %#v, want %q", capabilities, want)
}
