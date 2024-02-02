package main

import (
	"flag"
	"log"

	"github.com/hrmcardle0/aws-auto-remediation-setup/helpers"
	"github.com/hrmcardle0/aws-auto-remediation-setup/setup"
	"github.com/hrmcardle0/aws-auto-remediation-setup/teardown"
	"github.com/spf13/viper"
)

func main() {

	var destroy string

	flag.StringVar(&destroy, "destroy", "false", "Destroy Flag Set")
	flag.Parse()

	// set config
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Println("Error reading config file: ", err)
	}

	helpers.WorkingConfig.TargetRoleName = viper.GetString("target_role_name")
	helpers.WorkingConfig.Actions = viper.GetStringSlice("actions")
	helpers.WorkingConfig.ManagementRoleName = viper.GetString("management_role_name")
	helpers.WorkingConfig.EventBridgeRoleName = viper.GetString("eventbridge_role_name")
	helpers.WorkingConfig.EventBridgeRuleName = viper.GetString("eventbridge_rule_name")
	helpers.WorkingConfig.CentralEventBusArn = viper.GetString("central_event_bus_arn")
	helpers.WorkingConfig.TargetAccounts = viper.GetStringSlice("target_accounts")
	helpers.WorkingConfig.CentralAccount = viper.GetString("central_account")

	// Assume Role Setup
	// Assume the mgmt role in the target account in order to stand up our infra

	for _, account := range helpers.WorkingConfig.TargetAccounts {
		if err := setup.AssumeManagementRoleSetup(&helpers.WorkingConfig, account); err != nil {
			log.Fatal(err)
		}

		if destroy == "false" {
			// Target Infrastructure Setup
			// Use the mgmt role to create our infrastructure:
			// target-role - used by our auto-remediation playbook
			// eventbridge-rules - create eventbridge rules for each set of actions
			if err := setup.CreateTargetInfrastructureSetup(&helpers.WorkingConfig); err != nil {
				log.Fatal(err)
			}

		} else {
			// Infrastructure destroy
			// use the mgmt role to destroy our infrastructure
			if err := teardown.Teardown(&helpers.WorkingConfig); err != nil {
				log.Fatal(err)
			}
		}
	}

}
