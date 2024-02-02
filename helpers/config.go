package helpers

type Config struct {
	TargetRoleName      string   `mapstructure:"target_role_name"`
	SourceRoleArn       string   `mapstructure:"source_role_arn"`
	Actions             []string `mapstructure:"actions"`
	ManagementRoleName  string   `mapstructure:"management_role_name"`
	EventBridgeRoleName string   `mapstructure:"event_bridge_role_name"`
	EventBridgeRuleName string   `mapstructure:"event_bridge_rule_name"`
	CentralEventBusArn  string   `mapstructure:"central_event_bus_arn"`
	TargetAccounts      []string `mapstructure:"target_accounts"`
	CentralAccount      string   `mapstructure:"central_account"`
}

var WorkingConfig Config
