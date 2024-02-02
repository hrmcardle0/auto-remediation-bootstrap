package helpers

// eventbridge
type Detail struct {
	EventName []string `json:"eventName"`
}
type EventBridgePattern struct {
	Source []string `json:"source"`
	Detail Detail   `json:"detail"`
}

var EBP EventBridgePattern

var EventBridgeRuleNames []string
