package cmd

import (
"encoding/json"
"testing"

"github.com/opslevel/opslevel-go/v2025"
)

func TestNewToolResult(t *testing.T) {
// Test successful result with simple data
data := map[string]string{"key": "value"}
result, err := newToolResult(data, nil)

if err != nil {
t.Errorf("Expected no error, got %v", err)
}

if result == nil {
t.Fatal("Expected result to not be nil")
}

// Test with error
testErr := opslevel.NewGQLError(nil, "test error")
result, err = newToolResult(nil, testErr)

if err != nil {
t.Errorf("Expected no error from newToolResult, got %v", err)
}

if result == nil {
t.Fatal("Expected result to not be nil")
}
}

func TestSerializedComponentStructure(t *testing.T) {
// Test that serializedComponent can be instantiated and marshaled
component := serializedComponent{
Id:        "test-id",
Framework: "Django",
Language:  "Python",
Name:      "test-service",
Owner:     "test-team",
Url:       "https://example.com",
Level: serializedLevel{
Alias: "Gold",
Index: 2,
},
Lifecycle: serializedLifecycle{
Alias: "Production",
Index: 3,
},
Tier: serializedTier{
Alias: "Tier 1",
Index: 0,
},
}

// Marshal to JSON to verify structure
data, err := json.Marshal(component)
if err != nil {
t.Errorf("Failed to marshal component: %v", err)
}

// Unmarshal to verify round-trip
var decoded serializedComponent
err = json.Unmarshal(data, &decoded)
if err != nil {
t.Errorf("Failed to unmarshal component: %v", err)
}

if decoded.Name != "test-service" {
t.Errorf("Expected Name 'test-service', got '%s'", decoded.Name)
}

if decoded.Language != "Python" {
t.Errorf("Expected Language 'Python', got '%s'", decoded.Language)
}
}

func TestSerializedCheckStructure(t *testing.T) {
// Test that serializedCheck can be instantiated and marshaled
check := serializedCheck{
Id:          "check-id",
Name:        "test-check",
Owner:       "test-team",
Description: "Test description",
Notes:       "Test notes",
Enabled:     true,
Type:        "manual",
Level: serializedLevel{
Alias: "Silver",
Index: 1,
},
Category: "Security",
}

data, err := json.Marshal(check)
if err != nil {
t.Errorf("Failed to marshal check: %v", err)
}

var decoded serializedCheck
err = json.Unmarshal(data, &decoded)
if err != nil {
t.Errorf("Failed to unmarshal check: %v", err)
}

if decoded.Name != "test-check" {
t.Errorf("Expected Name 'test-check', got '%s'", decoded.Name)
}

if !decoded.Enabled {
t.Error("Expected Enabled to be true")
}
}

func TestSerializedInfrastructureResourceStructure(t *testing.T) {
// Test that serializedInfrastructureResource can be instantiated
resource := serializedInfrastructureResource{
Id:           "infra-id",
Name:         "test-db",
Owner:        "test-team",
Aliases:      []string{"alias1", "alias2"},
Schema:       "postgresql",
ProviderType: "aws",
}

data, err := json.Marshal(resource)
if err != nil {
t.Errorf("Failed to marshal infrastructure resource: %v", err)
}

var decoded serializedInfrastructureResource
err = json.Unmarshal(data, &decoded)
if err != nil {
t.Errorf("Failed to unmarshal infrastructure resource: %v", err)
}

if decoded.Name != "test-db" {
t.Errorf("Expected Name 'test-db', got '%s'", decoded.Name)
}

if len(decoded.Aliases) != 2 {
t.Errorf("Expected 2 aliases, got %d", len(decoded.Aliases))
}
}

func TestAllAccountMetadataStrings(t *testing.T) {
metadataTypes := AllAccountMetadataStrings()

if len(metadataTypes) == 0 {
t.Error("Expected at least one metadata type, got none")
}

// Verify expected types are present
expectedTypes := []string{"lifecycles", "levels", "tiers", "componentTypes"}
for _, expected := range expectedTypes {
found := false
for _, actual := range metadataTypes {
if actual == expected {
found = true
break
}
}
if !found {
t.Errorf("Expected metadata type '%s' not found", expected)
}
}
}

func TestComponentFilterStructure(t *testing.T) {
// Test simple filter
filter := componentFilter{
Key:  "name",
Type: "equals",
Arg:  "service-name",
}

data, err := json.Marshal(filter)
if err != nil {
t.Errorf("Failed to marshal filter: %v", err)
}

var decoded componentFilter
err = json.Unmarshal(data, &decoded)
if err != nil {
t.Errorf("Failed to unmarshal filter: %v", err)
}

if decoded.Key != "name" {
t.Errorf("Expected Key 'name', got '%s'", decoded.Key)
}

// Test composite filter
compositeFilter := componentFilter{
Connective: "and",
Predicates: []componentFilter{
{Key: "language", Type: "equals", Arg: "Python"},
{Key: "owner_id", Type: "equals", Arg: "team-123"},
},
}

data, err = json.Marshal(compositeFilter)
if err != nil {
t.Errorf("Failed to marshal composite filter: %v", err)
}

var decodedComposite componentFilter
err = json.Unmarshal(data, &decodedComposite)
if err != nil {
t.Errorf("Failed to unmarshal composite filter: %v", err)
}

if len(decodedComposite.Predicates) != 2 {
t.Errorf("Expected 2 predicates, got %d", len(decodedComposite.Predicates))
}
}
